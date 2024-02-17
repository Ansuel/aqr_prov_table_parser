#! /usr/bin/python

"""
MIT License

Copyright (c) 2024 Christian Marangi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
"""

# usage: aqr_prov_table_parser.py [-h] [--json] fw
#
# AQR Provision Table parser
#
# positional arguments:
#   fw          path to AQR Firmware
#
# options:
#   -h, --help  show this help message and exit
#   --json      Output parsed values in JSON format

import json
import os
import io
import argparse

PRIMARY_OFFSET_OFFSET = 0x8
PRIMARY_OFFSET_SHIFT = 12

HEADER_OFFSET = 0x300

PROV_TABLE_OFFSET = 0x680
PROV_TABLE_SIZE_MAX = 0x800

def extract_prov_table_offset(file):
	file.seek(PRIMARY_OFFSET_OFFSET)

	primary_offset = int.from_bytes(file.read(2), byteorder="little")
	primary_offset <<= PRIMARY_OFFSET_SHIFT

	# header format is:
	#  4 byte of padding
	#  3 byte for iram offset
	#  3 byte for iram size
	#  3 byte for dram offset
	#  3 byte for dram size
	# We are only interested in dram offset
	file.seek(primary_offset + HEADER_OFFSET + 4 + 3 + 3, os.SEEK_SET)

	dram_offset = int.from_bytes(file.read(3), byteorder="little")

	return primary_offset + dram_offset + PROV_TABLE_OFFSET

def parse_reg_val_mask(file, bugged=False):
	reg = int.from_bytes(file.read(2), byteorder="little")
	val = int.from_bytes(file.read(2), byteorder="little")
	mask = int.from_bytes(file.read(2), byteorder="little")
	reg_val_mask_tbl = { "reg": hex(reg), "val": hex(val), "mask": hex(mask) }
	if bugged:
		reg_val_mask_tbl["pos"] = file.tell() - 6
		reg_val_mask_tbl["bugged"] = True

	return reg_val_mask_tbl

# For some reason and I have no idea how some Provision Table
# are broken and provide reg-val-mask outside the length value
# 
# Example length is 0xF8 0x00 but there are 2 reg-val-mask define
# 
# FW correctly skip these (it has been verified that the value
# are actually NOT set)
# 
# This is problematic for the special value of 0x3
# To detect this assume the max priority is 3F
# And skip them if detected
# 
def check_bugged_section(file):
	pos = file.tell()
	header_0 = file.read(1)
	header_1 = file.read(1)
	file.seek(pos, os.SEEK_SET)
	if header_0[0] == 0x3 and header_1[0] & 0xc0:
		return parse_reg_val_mask(file, True)

def consume_subsection(file, regs_header):
	increment_length = regs_header & 0x80
	subsection_tbl = {}

	mmd_reg = regs_header & 0x7c
	mmd_reg >>= 2
	if mmd_reg > 0x1e:
		print("Read invalid MMD reg {}".format(hex(mmd_reg)))
		exit(1)
	subsection_tbl["mmd_reg"] = hex(mmd_reg)

	length = int.from_bytes(file.read(1)) * 2
	if increment_length:
		length += 1
	subsection_tbl["expected_length"] = length

	subsection_tbl["regs"] = []
	for _ in range(length):
		subsection_tbl["regs"].append(parse_reg_val_mask(file))

	# Check if for some reason the Provision Table is bugged
	# and have confusing header values
	bugged_reg = check_bugged_section(file)
	if bugged_reg:
		subsection_tbl["regs"].append(bugged_reg)

	return subsection_tbl

def consume_subsections(file, prov_table_offset):
	subsections = []
	while file.tell() <= prov_table_offset + PROV_TABLE_SIZE_MAX:
		regs_header = file.read(1)
		# Prov Table ended or we are in a new section
		if not regs_header[0] or regs_header[0] == 0x3:
			# Go back one and break loop
			file.seek(file.tell()-1, os.SEEK_SET)
			break

		# Assume subsection header in any other case
		if regs_header[0] & 0x7c:
			subsection = consume_subsection(file, regs_header[0])
			subsections.append(subsection)

	return subsections

# Each section ALWAYS stats with 0x3 followed by priority ID
# 
# Each section contains a contigious subection with a reg header and
# a number of values to write in the format reg val mask
# regs header is in format followed by the length of the subsection
# BIT(7) increment length by 1
# GENMASK(6, 2) MMD reg
# Data Length must always be multiplied by 2 (and eventually incremented)
# 
# Reg Value and Mask are all in big endian
# 
# Example
# 03 01 78 01 20 00 05 04 FF FF 85 C8 40 00 F0 00
# /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\
# || || || || || || || || || || || || || || || ||
# || || || || || || || || Mask  || || || || Mask
# || || || || || || Value       || || Value
# || || || || Address           Address
# || || || Data length (to increment if BIT 7 set and * 2)
# || || Reg Header (Length Increment, MMD reg)
# || Section priority 
# Section header
def parse_prov_table(file):
	prov_table_offset = extract_prov_table_offset(file)

	prov_table = []

	file.seek(prov_table_offset, os.SEEK_SET)

	while file.tell() <= prov_table_offset + PROV_TABLE_SIZE_MAX:
		# Check section header start
		section_header = file.read(1)

		# Assume Provision Table ended
		if not section_header[0]:
			break

		# Broken Provision Table??
		if section_header[0] != 0x3:
			print("Failed to parse Provision Table. Is the provision Table broken?")
			exit(1)

		# Section header is ALWAYS 0x3
		# Get priority ID
		priority = int.from_bytes(file.read(1))
		section_tbl = { "priority": priority }
		# Consume subsections until we find a new section header
		section_tbl["subsections"] = consume_subsections(file, prov_table_offset)

		prov_table.append(section_tbl)

	return prov_table

def print_prov_table(prov_table):
	for section in prov_table:
		print("Found a new section with priority {}".format(section["priority"]))

		for subsection in section["subsections"]:
			mmd_reg = subsection["mmd_reg"]
			for reg_val_mask in subsection["regs"]:
				print("MMD: {}\tReg: {}\tVal: {}\tMaks: {}".format(
					mmd_reg, reg_val_mask["reg"],
					reg_val_mask["val"],
					reg_val_mask["mask"]))
				if "bugged" in reg_val_mask:
					print("FOUND BUG IN PROVISION TABLE at pos {} for MMD reg {}".format(
						reg_val_mask["pos"], mmd_reg))

def main():
	parser = argparse.ArgumentParser(description="AQR Provision Table parser")
	parser.add_argument('aqr_firmware', metavar="fw", help="path to AQR Firmware")
	parser.add_argument('--json', dest="use_json", action="store_const", const=True,
				help="Output parsed values in JSON format")

	args = parser.parse_args()
	filename = args.aqr_firmware

	file = io.open(filename, "rb")
	prov_table = parse_prov_table(file)
	file.close()

	if args.use_json:
		print(json.dumps(prov_table))
	else:
		print_prov_table(prov_table)

if __name__ == "__main__":
    main()
