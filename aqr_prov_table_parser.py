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
import re

PRIMARY_OFFSET_OFFSET = 0x8
PRIMARY_OFFSET_SHIFT = 12

HEADER_OFFSET = 0x300

PROV_TABLE_OFFSET = 0x680
PROV_TABLE_SIZE_MAX = 0x800

ASSUMED_MAX_PRIORITY = 0x1f

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

def parse_reg_val_mask(file):
	reg = int.from_bytes(file.read(2), byteorder="little")
	val = int.from_bytes(file.read(2), byteorder="little")
	mask = int.from_bytes(file.read(2), byteorder="little")
	reg_val_mask_tbl = { "reg": hex(reg), "val": hex(val), "mask": hex(mask) }

	return reg_val_mask_tbl

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
	subsection_tbl["length"] = length

	subsection_tbl["regs"] = []
	for _ in range(length):
		subsection_tbl["regs"].append(parse_reg_val_mask(file))

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

def consume_padding(file, padding_len, prov_table_offset):
	padding_vals = []
	for _ in range(padding_len):
		if file.tell() > prov_table_offset + PROV_TABLE_SIZE_MAX:
			break

		padding_vals.append(file.read(1).hex())

	return padding_vals


# Each section ALWAYS stats with 0x3 followed by priority ID
# 
# The Values after the section header (0x3) are still a bit confusing
# Bits 7:5 are used for padding length, always a multiple of 2
# and should be multiply by 2. Rest is assumed to be priority or
# something related but it was notice that Bit 3 ALWAYS result in
# the value with the last bit set to zero (Example 0xffff -> 0x7fff)
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
# || Section priority (padding length + priority)
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
		# Get priority ID and padding info
		section_header_2 = file.read(1)

		priority = section_header_2[0] & ASSUMED_MAX_PRIORITY
		section_tbl = { "priority": priority }

		padding_len = ((section_header_2[0] & 0xe0) >> 5) * 2
		if (padding_len > 0):
			section_tbl["padding"] = { "length": padding_len,
						    "vals": consume_padding(file, padding_len, prov_table_offset)}

		# Consume subsections until we find a new section header
		section_tbl["subsections"] = consume_subsections(file, prov_table_offset)

		prov_table.append(section_tbl)

	return prov_table

def calculate_final_provision(prov_table, reference_tbl=None):
	final_provision = {}

	# Very inefficient way but can handle unsorted dictonary
	for priority in range(ASSUMED_MAX_PRIORITY):
		for section in prov_table:
			if section["priority"] != priority:
				continue

			for subsection in section["subsections"]:
				mmd_reg = subsection["mmd_reg"]
				if not mmd_reg in final_provision:
					final_provision[mmd_reg] = {}

				for reg_val_mask in subsection["regs"]:
					reg = reg_val_mask["reg"]

					if not reg in final_provision[mmd_reg]:
						final_provision[mmd_reg][reg] = { "val": "0x0" }

					val = int(final_provision[mmd_reg][reg]["val"], 16)
					val &= ~int(reg_val_mask["mask"], 16)
					val |= int(reg_val_mask["val"], 16)
					final_provision[mmd_reg][reg] =  { "val": hex(val) }
					if reference_tbl and mmd_reg in reference_tbl and reg in reference_tbl[mmd_reg]:
						final_provision[mmd_reg][reg]["reg_friendly_name"] = reference_tbl[mmd_reg][reg]

		for index, section in enumerate(prov_table):
			if section["priority"] == priority:
				prov_table.pop(index)

	return final_provision

def print_prov_table(prov_table):
	for section in prov_table:
		if "padding" in section:
			print("Found a new section with priority {} padded length {}".format(section["priority"], section["padding"]["length"]))
		else:
			print("Found a new section with priority {}".format(section["priority"]))

		for subsection in section["subsections"]:
			mmd_reg = subsection["mmd_reg"]
			for reg_val_mask in subsection["regs"]:
				print("MMD: {}\tReg: {}\tVal: {}\tMaks: {}".format(
					mmd_reg, reg_val_mask["reg"],
					reg_val_mask["val"],
					reg_val_mask["mask"]))

def print_final_prov_table(final_prov_table):
	# Very inefficent way to print ordered regs
	for mmd_reg in range(0x1f):
		mmd_reg = hex(mmd_reg)
		if not mmd_reg in final_prov_table:
			continue

		for reg in range(0xffff):
			reg = hex(reg)
			if not reg in final_prov_table[mmd_reg]:
				continue

			reg_friendly_name = ""
			if "reg_friendly_name" in final_prov_table[mmd_reg][reg]:
				reg_friendly_name = final_prov_table[mmd_reg][reg]["reg_friendly_name"]

			print("MMD: {}\tReg: {}\tVal: {}\t{}".format(
				mmd_reg, reg, final_prov_table[mmd_reg][reg]["val"], reg_friendly_name))

def parse_reference_regs(reference_regs_file):
	reference_tbl = {}
	pattern = re.compile("^([0-9]+)\.([0-9]+) (.*)$")

	file = io.open(reference_regs_file, "r")

	# File is in format mmd_reg.address friendly name
	for reg in file.readlines():
		res = pattern.findall(reg)[0]

		mmd_reg = hex(int(res[0]))
		reg = hex(int(res[1]))
		friendly_name = res[2]

		if not mmd_reg in reference_tbl:
			reference_tbl[mmd_reg] = {}

		reference_tbl[mmd_reg][reg] = friendly_name

		if int(mmd_reg, 16) == 1:
			for mmd_reg in ["0x8", "0x9", "0xa", "0xb"]:
				if not mmd_reg in reference_tbl:
					reference_tbl[mmd_reg] = {}

				reference_tbl[mmd_reg][reg] = friendly_name

	file.close()

	return reference_tbl

def parse_firmware(firmware_path):
	file = io.open(firmware_path, "rb")
	prov_table = parse_prov_table(file)
	file.close()

	return prov_table

def main():
	parser = argparse.ArgumentParser(description="AQR Provision Table parser")
	parser.add_argument('aqr_firmware', metavar="fw", help="path to AQR Firmware")
	parser.add_argument('--json', dest="use_json", action="store_const", const=True,
				help="Output parsed values in JSON format")
	parser.add_argument('--final-provision', dest="final_provision", action="store_const", const=True,
				help="Calculate final provision accounted of priority section and masked/ORed regs.")
	parser.add_argument('--reference-regs', dest="reference_regs_file", default="reference_regs.txt",
				help="Provide a reference regs file to add Friendly name to regs on dumping. Check the reference_regs.txt for the format. Only works with --final-provision")

	args = parser.parse_args()

	prov_table = parse_firmware(args.aqr_firmware)

	reference_tbl = None
	if args.reference_regs_file:
		reference_tbl = parse_reference_regs(args.reference_regs_file)

	# Final provision is what is actually applied to the Aquantia PHY
	# Accounted of section priority, and values with applied mask and or
	# with each section.
	if args.final_provision:
		prov_table = calculate_final_provision(prov_table, reference_tbl=reference_tbl)

	if args.use_json:
		print(json.dumps(prov_table))
	elif args.final_provision:
		print_final_prov_table(prov_table)
	else:
		print_prov_table(prov_table)

if __name__ == "__main__":
    main()
