/*
 * paperback: paper backup generator suitable for long-term storage
 * Copyright (C) 2018-2022 Aleksa Sarai <cyphar@cyphar.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

mod raw;

use std::{
    error::Error as StdError,
    fs::File,
    io::{self, prelude::*, BufReader, BufWriter},
    path,
    result::Result::{Ok, Err},
};


use anyhow::{anyhow, bail, ensure, Context, Error};
use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};

extern crate paperback_core;
use paperback_core::latest as paperback;

use paperback::{
    pdf::qr, wire, Backup, EncryptedKeyShard, FromWire, KeyShard, KeyShardCodewords, MainDocument,
    NewShardKind, ToPdf, UntrustedQuorum,
};

use pdfium_render::prelude::*;

// paperback-cli backup [--sealed] -n <QUORUM SIZE> -k <SHARDS> INPUT
fn backup_cli() -> Command {
    Command::new("backup")
            .about(r#"Create a paperback backup."#)
            .arg(Arg::new("sealed")
                .long("sealed")
                .help("Create a sealed backup, which cannot be expanded (have new shards be created) after creation.")
                .action(ArgAction::SetTrue))
            .arg(Arg::new("quorum-size")
                .short('n')
                .long("quorum-size")
                .value_name("QUORUM SIZE")
                .help("Number of shards required to recover the document (must not be larger than --shards).")
                .action(ArgAction::Set)
                .required(true))
            .arg(Arg::new("shards")
                .short('k')
                .long("shards")
                .value_name("NUM SHARDS")
                .help("Number of shards to create (must not be smaller than --quorum-size).")
                .action(ArgAction::Set)
                .required(true))
            .arg(Arg::new("INPUT")
                .help(r#"Path to file containing secret data to backup ("-" to read from stdin)."#)
                .action(ArgAction::Set)
                .allow_hyphen_values(true)
                .required(true)
                .index(1))
}

fn backup(matches: &ArgMatches) -> Result<(), Error> {
    let sealed = matches.get_flag("sealed");
    let quorum_size: u32 = matches
        .get_one::<String>("quorum-size")
        .context("required --quorum-size argument not provided")?
        .parse()
        .context("--quorum-size argument was not an unsigned integer")?;
    let num_shards: u32 = matches
        .get_one::<String>("shards")
        .context("required --quorum-size argument not provided")?
        .parse()
        .context("--shards argument was not an unsigned integer")?;
    let input_path = matches
        .get_one::<String>("INPUT")
        .context("required INPUT argument not provided")?;

    let (mut stdin_reader, mut file_reader);
    let input: &mut dyn Read = if input_path == "-" {
        stdin_reader = io::stdin();
        &mut stdin_reader
    } else {
        file_reader = File::open(input_path)
            .with_context(|| format!("failed to open secret data file '{}'", input_path))?;
        &mut file_reader
    };
    let mut buffer_input = BufReader::new(input);

    let mut secret = Vec::new();
    buffer_input
        .read_to_end(&mut secret)
        .with_context(|| format!("failed to read secret data from '{}'", input_path))?;

    let backup = if sealed {
        Backup::new_sealed(quorum_size, &secret)
    } else {
        Backup::new(quorum_size, &secret)
    }?;
    let main_document = backup.main_document().clone();
    let shards = (0..num_shards)
        .map(|_| backup.next_shard().unwrap())
        .map(|s| (s.id(), s.encrypt().unwrap()))
        .collect::<Vec<_>>();

    main_document
        .to_pdf()?
        .save(&mut BufWriter::new(File::create(format!(
            "main_document-{}.pdf",
            main_document.id()
        ))?))?;

    for (shard_id, (shard, codewords)) in shards {
        (shard, codewords)
            .to_pdf()?
            .save(&mut BufWriter::new(File::create(format!(
                "key_shard-{}-{}.pdf",
                main_document.id(),
                shard_id
            ))?))?;
    }

    Ok(())
}

fn read_multiline<S: AsRef<str>>(prompt: S) -> Result<String, Error> {
    print!("{}: ", prompt.as_ref());
    io::stdout().flush()?;

    let buffer_stdin = BufReader::new(io::stdin());
    Ok(buffer_stdin
        .lines()
        .take_while(|s| match s {
            Ok(line) => !line.is_empty(),
            Err(_) => false,
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| anyhow!("failed to read data: {}", err))?
        .join("\n"))
}

fn read_multibase<S: AsRef<str>, T: FromWire>(prompt: S) -> Result<T, Error> {
    T::from_wire_multibase(
        wire::multibase_strip(read_multiline(prompt)?)
            .map_err(|err| anyhow!("failed to strip out non-multibase characters: {}", err))?,
    )
    .map_err(|err| anyhow!("failed to parse data: {}", err))
}

fn read_codewords<S: AsRef<str>>(prompt: S) -> Result<KeyShardCodewords, Error> {
    Ok(read_multiline(prompt)?
        .split_whitespace()
        .map(|s| s.to_owned())
        .collect::<Vec<_>>())
}

fn read_multibase_qr<S: AsRef<str>, T: FromWire>(prompt: S) -> Result<T, Error> {
    let prompt = prompt.as_ref();
    let mut joiner = qr::Joiner::new();
    while !joiner.complete() {
        let part: qr::Part = read_multibase(format!(
            "{} ({} codes remaining)",
            prompt,
            match joiner.remaining() {
                None => "unknown number of".to_string(),
                Some(n) => n.to_string(),
            }
        ))?;
        joiner.add_part(part)?;
    }
    T::from_wire(joiner.combine_parts()?)
        .map_err(|err| anyhow!("parse inner qr code data: {}", err))
}

// paperback-cli recover --interactive
fn recover_cli() -> Command {
    Command::new("recover")
        .about(r#"Recover a paperback backup."#)
        // Mode flags
        .arg(
            Arg::new("interactive")
                .long("interactive")
                .help("Ask for data stored in QR codes interactively rather than scanning images.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("main-document")
                .long("main-document")
                .help("The main PDF document to recover from.")
                .value_name("PDF")
                .action(ArgAction::Set),
        )
        // Key shards, required only if main-document is provided
        .arg(
            Arg::new("shards")
                .long("shards")
                .help("Comma-separated list of key shard PDF files.")
                .value_name("SHARDS")
                .required_unless_present("interactive")
                .use_value_delimiter(true)
                .action(ArgAction::Append),
        )
        // Output file (always required)
        .arg(
            Arg::new("OUTPUT")
                .help(r#"Path to write recovered secret data to ("-" to write to stdout)."#)
                .action(ArgAction::Set)
                .allow_hyphen_values(true)
                .required(true)
                .index(1),
        )
        // Only one mode can be chosen
        .group(
            ArgGroup::new("mode")
                .args(&["interactive", "main-document"])
                .required(true)
                .multiple(false),
        )

}

fn scan_key_shard(pdf_file: &String) -> Result<KeyShard, Error> {
    let path = path::Path::new(pdf_file);
    let mut jpg_path = path.to_path_buf();
    jpg_path.set_extension("jpg");

    ensure!(
        path.exists(),
        "key shard document '{}' does not exist",
        path.display()
    );

    ensure!(
        path.extension().and_then(|s| s.to_str()) == Some("pdf"),
        "key shard document '{}' is not a PDF file",
        path.display()
    );

    println!("Scanning key shard document from '{}'...", path.display());

    // Initialize Pdfium
    let pdfium = Pdfium::new(
        Pdfium::bind_to_system_library().or_else(|_| Pdfium::bind_to_system_library())?,
    );

    // Load the PDF document
    let document = pdfium.load_pdf_from_file(&path, None)?;

    let page = document.pages().first()?;

    let mut codewords: Vec<String> = Vec::new();
    // Keep track of whether we've seen the 'Codewords' word
    let mut codewords_seen: bool = false;
    let mut should_skip = false;

    let texts_iter = page
        .objects()
        .iter()
        .filter_map(|object| object.as_text_object().map(|object| object.text()))
        .enumerate();

    for (_, text) in texts_iter {
        if codewords.len() == 24 {
            break;
        }

        let trimmed = text.trim();

        if trimmed.is_empty() {
            continue;
        }

        if codewords_seen {
            if should_skip {
                should_skip = false;
                continue;
            }
            if text.contains("Shard") || text.contains("Document") {
                should_skip = true;
                continue;
            }
            codewords.push(trimmed.to_string());
            continue;
        }

        if trimmed.eq("Codewords") {
            codewords_seen = true;
            should_skip = true;
            continue;
        }
    }

    ensure!(
        !codewords.is_empty(),
        "failed to find codewords in key shard document"
    );

    println!("Converting key shard document to image...");
    let render_config = PdfRenderConfig::new()
        .set_target_width(2048)
        .rotate_if_landscape(PdfPageRenderRotation::Degrees90, true);
    let image = page.render_with_config(&render_config)?.as_image();

    image.save(&jpg_path)?;
    println!("Saved {}", jpg_path.to_string_lossy());

    println!("Decoding encrypted key shard document QR code...");

    let img = image::open(jpg_path)?;

    let decoder = bardecoder::default_decoder();
    let barcodes = decoder.decode(&img);

    for barcode in barcodes.iter().filter(|b| b.is_ok()) {
        let bc = barcode.as_ref().unwrap();

        let encrypted_shard: EncryptedKeyShard = wire::FromWire::from_wire_multibase(
            wire::multibase_strip(bc)
                .map_err(|err| anyhow!("failed to strip out non-multibase characters: {}", err))?,
        )
        .map_err(|err| anyhow!("failed to parse data: {}", err))?;

        println!(
            "Key shard {} checksum: {}",
            pdf_file,
            encrypted_shard.checksum_string()
        );

        let shard = encrypted_shard
            .decrypt(&codewords)
            .map_err(|err| anyhow!(err))
            .with_context(|| format!("decrypting key shard {}", pdf_file))?;
        return Ok(shard);
    }

    bail!("failed to decode any QR codes from key shard document");
}

fn scan_main_document(pdf_file: &String) -> Result<MainDocument, Error> {
    let path = path::Path::new(pdf_file);
    let mut jpg_path = path.to_path_buf();
    jpg_path.set_extension("jpg");

    ensure!(
        path.exists(),
        "main document '{}' does not exist",
        path.display()
    );

    ensure!(
        path.extension().and_then(|s| s.to_str()) == Some("pdf"),
        "main document '{}' is not a PDF file",
        path.display()
    );

    println!("Scanning main document from '{}'...", path.display());

    // Initialize Pdfium
    let pdfium = Pdfium::new(
        Pdfium::bind_to_system_library().or_else(|_| Pdfium::bind_to_system_library())?,
    );

    // Load the PDF document
    let document = pdfium.load_pdf_from_file(&path, None)?;

    let page = document.pages().first()?;

    let mut document_code = String::new();
    // Keep track of whether we've seen the 'Document' word
    let mut document_seen = false;

    let texts_iter = page
        .objects()
        .iter()
        .filter_map(|object| object.as_text_object().map(|object| object.text()))
        .enumerate();

    for (_, text) in texts_iter {
        let trimmed = text.trim();

        if trimmed.is_empty() {
            continue;
        }

        if document_seen && document_code.is_empty() {
            document_code = trimmed.to_string();
            println!("Document code: {}", document_code);
            break;
        }

        if trimmed == "Document" && document_code.is_empty() {
            document_seen = true;
            continue;
        }
    }

    ensure!(
        !document_code.is_empty(),
        "failed to find document code in main document"
    );

    println!("Converting main document to image...");
    let render_config = PdfRenderConfig::new()
        .set_target_width(2048)
        .rotate_if_landscape(PdfPageRenderRotation::Degrees90, true);
    let image = page.render_with_config(&render_config)?.as_image();

    image.save(&jpg_path)?;
    println!("Saved {}", jpg_path.to_string_lossy());

    println!("Decoding main document QR codes...");

    let img = image::open(jpg_path)?;

    let decoder = bardecoder::default_decoder();
    let barcodes = decoder.decode(&img);
    let mut joiner = qr::Joiner::new();

    let document_code_part: qr::Part = wire::FromWire::from_wire_multibase(
        wire::multibase_strip(document_code)
            .map_err(|err| anyhow!("failed to strip out non-multibase characters: {}", err))?,
    )
    .map_err(|err| anyhow!("failed to parse data: {}", err))?;

    joiner.add_part(document_code_part)?;

    for barcode in barcodes.iter().filter(|b| b.is_ok()) {
        if joiner.complete() {
            break;
        }

        let bc = barcode.as_ref().unwrap();

        let bc_code_part: qr::Part = wire::FromWire::from_wire_multibase(
            wire::multibase_strip(bc)
                .map_err(|err| anyhow!("failed to strip out non-multibase characters: {}", err))?,
        )
        .map_err(|err| anyhow!("failed to parse data: {}", err))?;

        joiner.add_part(bc_code_part)?;
    }

    ensure!(joiner.complete(), "not all QR code parts were found");

    FromWire::from_wire(joiner.combine_parts()?)
        .map_err(|err| anyhow!("failed to parse main document data: {}", err))
}

fn recover_from_pdf(
    main_doc_file: &String,
    key_shard_files: &[&String],
) -> Result<UntrustedQuorum, Error> {
    let mut quorum = UntrustedQuorum::new();

    let main_document: MainDocument = scan_main_document(&main_doc_file)?;
    let quorum_size = main_document.quorum_size();
    // TODO: Ask the user to input the checksum...
    println!(
        "Main document checksum: {}",
        main_document.checksum_string()
    );

    println!("Document ID: {}", main_document.id());
    println!("{} key shards required.", quorum_size);
    ensure!(
        key_shard_files.len() >= quorum_size as usize,
        "not enough key shard files provided (have {}, need {})",
        key_shard_files.len(),
        quorum_size
    );

    quorum.main_document(main_document);

    while quorum.num_untrusted_shards() < quorum_size as usize {
        let idx = quorum.num_untrusted_shards() as usize;
        let shard = scan_key_shard(key_shard_files[idx])?;
        println!("Loaded key shard {}.", shard.id());
        quorum.push_shard(shard);
    }

    Ok(quorum)
}

fn recover_interactive() -> Result<UntrustedQuorum, Error> {
    let main_document: MainDocument = read_multibase_qr("Enter a main document code")?;
    let quorum_size = main_document.quorum_size();
    // TODO: Ask the user to input the checksum...
    println!(
        "Main document checksum: {}",
        main_document.checksum_string()
    );

    println!("Document ID: {}", main_document.id());
    println!("{} key shards required.", quorum_size);

    let mut quorum = UntrustedQuorum::new();
    quorum.main_document(main_document);
    while quorum.num_untrusted_shards() < quorum_size as usize {
        let idx = quorum.num_untrusted_shards() as u32;
        let encrypted_shard: EncryptedKeyShard = read_multibase(format!(
            "Quorum contains [{}] key shards.\nEnter key shard {} of {}",
            quorum
                .untrusted_shards()
                .map(KeyShard::id)
                .collect::<Vec<_>>()
                .join(" "),
            idx + 1,
            quorum_size
        ))?;
        // TODO: Ask the user to input the checksum...
        println!(
            "Key shard {} checksum: {}",
            idx + 1,
            encrypted_shard.checksum_string()
        );

        let codewords = read_codewords(format!("Enter key shard {} codewords", idx + 1))?;
        let shard = encrypted_shard
            .decrypt(&codewords)
            .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
            .with_context(|| format!("decrypting key shard {}", idx + 1))?;

        println!("Loaded key shard {}.", shard.id());
        quorum.push_shard(shard);
    }

    Ok(quorum)
}

fn recover(matches: &ArgMatches) -> Result<(), Error> {
    let interactive = matches.get_flag("interactive");

    let output_path = matches
        .get_one::<String>("OUTPUT")
        .context("required OUTPUT argument not provided")?;

    let quorum: UntrustedQuorum = if !interactive {
        let main_doc_file = matches
            .get_one::<String>("main-document")
            .context("required --main-document argument not provided")?;

        let key_shard_files: Vec<&String> = matches
            .get_many::<String>("shards")
            .context("required --shards argument not provided")?
            .collect();

        recover_from_pdf(main_doc_file, &key_shard_files)?
    } else {
        recover_interactive()?
    };

    let quorum = quorum.validate().map_err(|err| {
        anyhow!(
            "quorum failed to validate -- possible forgery! {}; groupings: {:?}",
            err.message,
            err.as_groups()
        )
    })?;

    let secret = quorum
        .recover_document()
        .context("recovering secret data")?;

    let (mut stdout_writer, mut file_writer);
    let output_file: &mut dyn Write = if output_path == "-" {
        stdout_writer = io::stdout();
        &mut stdout_writer
    } else {
        file_writer = File::create(output_path)
            .with_context(|| format!("failed to open output file '{}' for writing", output_path))?;
        &mut file_writer
    };

    output_file
        .write_all(&secret)
        .context("write secret data to file")?;

    Ok(())
}

fn new_shards(new_shard_types: impl IntoIterator<Item = NewShardKind>) -> Result<(), Error> {
    let mut quorum = UntrustedQuorum::new();
    loop {
        let idx = quorum.num_untrusted_shards() as u32;
        let encrypted_shard: EncryptedKeyShard = read_multibase(match quorum.quorum_size() {
            None => format!(
                "Quorum contains no key shards.\nEnter key shard {}",
                idx + 1
            ),
            Some(n) => format!(
                "Quorum contains [{}] key shards.\nEnter key shard {} of {}",
                quorum
                    .untrusted_shards()
                    .map(KeyShard::id)
                    .collect::<Vec<_>>()
                    .join(" "),
                idx + 1,
                n,
            ),
        })?;
        // TODO: Ask the user to input the checksum...
        println!(
            "Key shard {} checksum: {}",
            idx + 1,
            encrypted_shard.checksum_string()
        );

        let codewords = read_codewords(format!("Enter key shard {} codewords", idx + 1))?;
        let shard = encrypted_shard
            .decrypt(&codewords)
            .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
            .with_context(|| format!("decrypting key shard {}", idx + 1))?;

        println!("Loaded key shard {}.", shard.id());
        quorum.push_shard(shard);

        if idx + 1
            >= quorum
                .quorum_size()
                .expect("quorum_size should be set after adding a key shard")
        {
            break;
        }
    }

    let quorum = quorum.validate().map_err(|err| {
        anyhow!(
            "quorum failed to validate -- possible forgery! {}; groupings: {:?}",
            err.message,
            err.as_groups()
        )
    })?;

    let new_shards = new_shard_types
        .into_iter()
        .map(|new| {
            let s = quorum.new_shard(new).context("minting new key shards")?;
            Ok((
                s.document_id(),
                s.id(),
                s.encrypt().expect("encrypt new shard"),
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    for (document_id, shard_id, (shard, codewords)) in new_shards {
        (shard, codewords)
            .to_pdf()?
            .save(&mut BufWriter::new(File::create(format!(
                "key_shard-{}-{}.pdf",
                document_id, shard_id
            ))?))?;
    }

    Ok(())
}

// paperback-cli expand-shards --interactive -n <SHARDS>
fn expand_shards_cli() -> Command {
    Command::new("expand-shards")
            .about(r#"Create new key shards from a quorum of old key shards. The new key shards are separate to existing key shards, which means you are increasing the number of shards in circulation. This operation is recommended when you wish to add a new key shard holder to an existing quorum (and you are still confident that no more than N-1 shard holders will conspire against you)."#)
            .arg(Arg::new("interactive")
                .long("interactive")
                .help(r#"Ask for data stored in QR codes interactively rather than scanning images."#)
                .action(ArgAction::SetTrue)
                // TODO: Make this optional.
                .required(true))
            .arg(Arg::new("new-shards")
                .short('n')
                .long("new-shards")
                .value_name("NUM SHARDS")
                .help(r#"Number of new shards to create."#)
                .action(ArgAction::Set)
                .required(true))
}

fn expand_shards(matches: &ArgMatches) -> Result<(), Error> {
    let num_new_shards: u32 = matches
        .get_one::<String>("new-shards")
        .context("required --new-shards argument not provided")?
        .parse()
        .context("--new-shards argument was not an unsigned integer")?;
    new_shards((0..num_new_shards).map(|_| NewShardKind::NewShard))
}

// paperback-cli recreate-shards --interactive <SHARD-ID>...
fn recreate_shards_cli() -> Command {
    Command::new("recreate-shards")
            .about(r#"Re-create key shards with a given identifier from a quorum of old key shards. The re-created key shards are identical to the original versions of said key shards. This operation is recommended when one of the key shard holders lose their key shard and need a replacement (this ensures that they cannot fool you into getting an distinct new shard in addition to the original)."#)
            .arg(Arg::new("interactive")
                .long("interactive")
                .help(r#"Ask for data stored in QR codes interactively rather than scanning images."#)
                .action(ArgAction::SetTrue)
                // TODO: Make this optional.
                .required(true))
            .arg(Arg::new("shard-ids")
                .value_name("SHARD ID")
                .help(r#"Shard identifier(s) of the shard(s) to recreate."#)
                .action(ArgAction::Append)
                .required(true))
}

fn recreate_shards(matches: &ArgMatches) -> Result<(), Error> {
    let new_shard_list = matches
        .get_many::<String>("shard-ids")
        .context("required shard id arguments not given")?
        .cloned()
        .map(NewShardKind::ExistingShard);
    new_shards(new_shard_list)
}

// paperback-cli reprint --interactive [--main-document|--shard]
fn reprint_cli() -> Command {
    Command::new("reprint")
        .about(r#""Re-print" a paperback document by generating a new PDF from an existing PDF."#)
        .arg(
            Arg::new("interactive")
                .long("interactive")
                .help("Ask for data stored in QR codes interactively rather than scanning images.")
                .action(ArgAction::SetTrue)
                // TODO: Make this optional.
                .required(true),
        )
        .arg(
            Arg::new("main-document")
                .long("main-document")
                .help(r#"Reprint a paperback main document."#)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("shard")
                .long("shard")
                .help(r#"Reprint a paperback key shard."#)
                .action(ArgAction::SetTrue),
        )
}

fn reprint(matches: &ArgMatches) -> Result<(), Error> {
    let interactive = matches.get_flag("interactive");
    ensure!(interactive, "PDF scanning not yet implemented");

    let mut main_document: MainDocument;
    let mut shard_pair: (EncryptedKeyShard, KeyShardCodewords);
    let (pdf, path_basename): (&mut dyn ToPdf, String) = match matches
        .get_one::<clap::Id>("type")
        .context("neither --main-document nor --shard provided")?
        .as_str()
    {
        "main-document" => {
            main_document = read_multibase_qr("Enter a main document code")?;
            // TODO: Ask the user to input the checksum...
            println!(
                "Main document checksum: {}",
                main_document.checksum_string()
            );

            let pathname = format!("main-document-{}.pdf", main_document.id());
            (&mut main_document, pathname)
        }
        "shard" => {
            let encrypted_shard: EncryptedKeyShard = read_multibase("Enter key shard")?;
            // TODO: Ask the user to input the checksum...
            println!("Key shard checksum: {}", encrypted_shard.checksum_string());
            let codewords = read_codewords("Key shard codewords")?;

            let shard = encrypted_shard
                .decrypt(codewords.clone())
                .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
                .with_context(|| "decrypting shard")?;
            let pathname = format!("key-shard-{}-{}.pdf", shard.document_id(), shard.id());

            shard_pair = (encrypted_shard, codewords);
            (&mut shard_pair, pathname)
        }
        // We should never reach here.
        _ => bail!("neither --shard nor --main-document type flags passed"),
    };

    pdf.to_pdf()?
        .save(&mut BufWriter::new(File::create(path_basename)?))?;

    Ok(())
}

fn cli() -> Command {
    Command::new("paperback-cli")
        .version("0.0.0")
        .author("Aleksa Sarai <cyphar@cyphar.com>")
        .about("Operate on a paperback backup using a basic CLI interface.")
        // paperback-cli backup [--sealed] -n <QUORUM SIZE> -k <SHARDS> INPUT
        .subcommand(backup_cli())
        // paperback-cli recover --interactive
        .subcommand(recover_cli())
        // paperback-cli expand-shards --interactive -n <SHARDS>
        .subcommand(expand_shards_cli())
        // paperback-cli recreate-shards --interactive <SHARD-ID>...
        .subcommand(recreate_shards_cli())
        // paperback-cli reprint --interactive [--main-document|--shard]
        .subcommand(reprint_cli())
        // paperback-cli raw ...
        .subcommand(raw::subcommands())
}

fn main() -> Result<(), Box<dyn StdError>> {
    let mut app = cli();

    match app.get_matches_mut().subcommand() {
        Some(("raw", sub_matches)) => raw::submatch(&mut app, sub_matches),
        Some(("backup", sub_matches)) => backup(sub_matches),
        Some(("recover", sub_matches)) => recover(sub_matches),
        Some(("expand-shards", sub_matches)) => expand_shards(sub_matches),
        Some(("recreate-shards", sub_matches)) => recreate_shards(sub_matches),
        Some(("reprint", sub_matches)) => reprint(sub_matches),
        Some((subcommand, _)) => {
            // We should never end up here.
            app.print_help()?;
            Err(anyhow!("unknown subcommand '{}'", subcommand))
        }
        None => {
            app.print_help()?;
            Err(anyhow!("no subcommand specified"))
        }
    }?;

    Ok(())
}

#[test]
fn verify_cli() {
    cli().debug_assert();
}
