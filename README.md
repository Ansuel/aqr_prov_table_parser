# AQR Provision Table Parser

This script, `aqr_prov_table_parser.py`, is a Python script designed to parse and extract information from an AQR provision table.

## Usage

The script can be run directly from the command line as follows:

```bash
usage: aqr_prov_table_parser.py [-h] [--json] fw

AQR Provision Table parser

positional arguments:
  fw          path to AQR Firmware

options:
  -h, --help  show this help message and exit
  --json      Output parsed values in JSON format
```

## AQR Provision Table Format

The AQR provision table has a specific format. Here's a breakdown of its structure:

- **Section Start**: Each section always starts with `0x3` followed by a priority ID.
- **Subsection**: Each section contains a contiguous subsection with a register header and a number of values to write in the format `reg val mask`.
- **Regs Header**: The regs header is followed by the length of the subsection.
  
  BIT(7) is set, the length is incremented by 1.
  
  GENMASK(6, 2) represents the MMD reg.

  Data Length must always be multiplied by 2 (and eventually incremented)
- **Reg Value and Mask**: The reg value and mask are all in big endian.

Here's an example of the AQR provision table format:

```
03 01 78 01 20 00 05 04 FF FF 85 C8 40 00 F0 00
/\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\
|| || || || || || || || || || || || || || || ||
|| || || || || || || || Mask  || || || || Mask
|| || || || || || Value       || || Value
|| || || || Address            Address
|| || || Data length (to increment if BIT 7 set and * 2)
|| || Reg Header (Length Increment, MMD reg)
|| Section priority
Section header
```
## BUG Discovery on Provision Table

While creating the parser it was made a funny and interesting discovery.

Given the described format, the **Regs Header** gives reference of how
much regs the subsection defines.

It was found that some Table use a **Regs Header** that define one length
but actually define more regs in the subsection, resulting in the FW
actually ignoring them and not applying the regs.

The script provide some workaround for this and also print a warning if
this BUG is detected.

This was tested that by setting the correct **Regs Header**, the regs are
correctly applied hence it seems there is a problem with the tool that
generates this table or who tweaks them made some mistake and embedded
a bugger table.

## Contributing

Contributions are welcome. Please submit a pull request with any enhancements.

## License

This project is licensed under the terms of the MIT license.
