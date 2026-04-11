#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

BANNED_TRIGGERS = %w[pull_request_target workflow_run].freeze

def workflow_paths
  paths = Dir[".github/workflows/*.{yml,yaml}"]
  if Dir.exist?(".github/actions")
    paths.concat(Dir[".github/actions/**/*.{yml,yaml}"])
  end
  paths.sort
end

def extract_triggers(on_value)
  case on_value
  when String, Symbol
    [on_value.to_s]
  when Array
    on_value.flat_map { |value| extract_triggers(value) }
  when Hash
    on_value.keys.map(&:to_s)
  else
    []
  end
end

def workflow_on_value(doc)
  return nil unless doc.is_a?(Hash)

  doc["on"] || doc[:on] || doc[true]
end

violations = []

workflow_paths.each do |path|
  doc = YAML.safe_load(
    File.read(path),
    permitted_classes: [],
    permitted_symbols: [],
    aliases: false
  ) || {}
  banned = extract_triggers(workflow_on_value(doc)) & BANNED_TRIGGERS
  next if banned.empty?

  violations << "#{path}: banned workflow trigger(s): #{banned.uniq.sort.join(', ')}"
end

if violations.empty?
  puts "workflow trigger policy OK"
  exit 0
end

warn violations.join("\n")
exit 1
