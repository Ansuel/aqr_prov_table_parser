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
  The Values after the section header (0x3) are still a bit confusing.

  Bits 7:5 are used for padding length, always a multiple of 2
  and should be multiply by 2.

  Rest is assumed to be priority or something related but it was notice that Bit 3 ALWAYS result in
  the value with the last bit set to zero (Example 0xffff -> 0x7fff)
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
|| Section priority (padding length + priority)
Section header
```
## Confusion and Investigation on Priority Section

It looks like Bugged section werent' actually bugged but a very strange
format that wasn't clear from the start.

It seems the Priority Section is not actually only Priority but much worse.

It really seems to contain all sort of bits that declares property of the
subsections.

For example the last 3 bits declare the padding length of each subsection.
Max padding length value is 8 and the logic is 7:5 value * 2.
Accepted padding lenght is always a multiple of 2 hence the possible padding
are 2, 4, 6 and 8.

The example format it was notice is the following:
 03 41 01 01 01 01 F8 01 8D C0 20 00 20 00
 - 0x03 section header
 - 0x41 BIT 6 = padding 2 * 2 = 4
 - 0x01 0x01 0x01 0x01 padding of 4
 - 0xf8 reg header
 - 0x01 data length
 ...

On top of this with further research I notice the first bits
could also have different meaning than priority.

BIT 1 seems to always trigger a write
BIT 3 seems to always zero the last bit (0xffff -> 0x7fff)

Anyone having any clue of this would be very helpful to better understand and
oarse the section.

## Contributing

Contributions are welcome. Please submit a pull request with any enhancements.

## License

This project is licensed under the terms of the MIT license.
