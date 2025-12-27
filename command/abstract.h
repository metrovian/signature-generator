#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <cmath>
#include <csignal>
#include <functional>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <CLI/CLI.hpp>

class command_abstract {
protected: /* command parser */
	CLI::App *command_parser_;
	std::vector<std::unique_ptr<command_abstract>> commands_;

protected: /* file */
	static int8_t read_binary(const std::string &path, std::vector<uint8_t> &binary);
	static int8_t write_binary(const std::string &path, std::vector<uint8_t> &binary);
	static int8_t read_text(const std::string &path, std::string &text);
	static int8_t write_text(const std::string &path, std::string &text);

protected: /* subcommand */
	int8_t setup_subcommand(std::unique_ptr<command_abstract> command);
	int8_t select_subcommand();

public: /* abstract */
	virtual ~command_abstract() {}

public: /* abstract */
	virtual void setup(CLI::App *parent) = 0;
	virtual void run() = 0;
};