# frozen_string_literal: true

require 'openssl'

class PBKDF2
  VERSION = '0.0.1'

  def self.hex_string(options = {})
    new(options).calculate
  end

  def initialize(options)
    @options = options
    validate_options
    setup_hash_function
    setup_key_length
  end

  def calculate
    blocks_needed = calculate_blocks_needed
    value = calculate_value(blocks_needed)
    truncate_value(value)
  end

  private

  attr_reader :options

  def validate_options
    validate_mandatory_keys
    validate_key_length
    validate_hash_function
    validate_iterations
  end

  def validate_mandatory_keys
    mandatory_keys = %i[password salt iterations key_length hash_function]
    mandatory_keys.each do |key|
      raise ArgumentError, ":#{key} is not set" if options[key].nil?
    end
  end

  def validate_key_length
    raise ArgumentError, 'Key is too short (< 1)' if options[:key_length] < 1
  end

  def validate_hash_function
    hash_function_instance = options[:hash_function].new
    max_key_length = (2**32 - 1) * hash_function_instance.size
    raise ArgumentError, 'key is too long for hash function' if options[:key_length] / 8 > max_key_length

    @options[:hash_function] = hash_function_instance
  end

  def validate_iterations
    raise ArgumentError, "iterations can't be less than 1" if options[:iterations] < 1
  end

  def setup_hash_function
    @options[:hash_function] = options[:hash_function].new
  end

  def setup_key_length
    @options[:key_length] /= 8
  end

  def calculate_blocks_needed
    (options[:key_length].to_f / options[:hash_function].size).ceil
  end

  def calculate_value(blocks_needed)
    value = String.new

    1.upto(blocks_needed) do |block_num|
      value << calculate_block(block_num)
    end

    value
  end

  def truncate_value(value)
    value.slice(0, options[:key_length]).unpack1('H*')
  end

  def prf(data)
    OpenSSL::HMAC.digest(options[:hash_function], options[:password], data)
  end

  def calculate_block(block_num)
    u = prf(options[:salt] + [block_num].pack('N'))
    ret = u
    2.upto(options[:iterations]) do
      u = prf(u)
      ret ^= u
    end
    ret
  end
end

class String
  def xor_impl(other)
    result = RUBY_VERSION >= '1.9' ? ''.encode('ASCII-8BIT') : []
    o_bytes = other.bytes.to_a
    bytes.each_with_index do |c, i|
      result << (c ^ o_bytes[i])
    end
    RUBY_VERSION >= '1.9' ? result : result.pack('C*')
  end

  private :xor_impl

  def ^(other)
    raise ArgumentError, "Can't bitwise-XOR a String with a non-String" unless other.is_a? String
    raise ArgumentError, "Can't bitwise-XOR strings of different length" unless length == other.length

    xor_impl(other)
  end
end
