# THIS IS A MINIMALLY MODIFIED IMPLEMENTATION OF PBKDF2, ORIGINALLY IMPLEMENTED BY
# Sam Quigley. ORIGINAL IMPLEMENTATION AVAILABLE AT:
# https://github.com/emerose/pbkdf2-ruby
#
# Copyright (c) 2008 Sam Quigley <quigley@emerose.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# This license is sometimes referred to as "The MIT License"

require 'openssl'

class PBKDF2
  VERSION = "0.0.1"
  def self.hex_string(options = {})

    yield self if block_given?

    # Raise errors for unset options, all are mandatory
    raise ArgumentError, ":password is not set" if options[:password].nil?
    raise ArgumentError, ":salt is not set" if options[:salt].nil?
    raise ArgumentError, ":iterations is not set" if options[:iterations].nil?
    raise ArgumentError, ":key_length is not set" if options[:key_length].nil?
    raise ArgumentError, ":hash_function is not set" if options[:hash_function].nil?

    options[:hash_function] = options[:hash_function].new
    validate(options)
    options[:key_length] = options[:key_length]/8

    calculate!(options)
  end

  def self.validate(options)
    raise ArgumentError, "Key is too short (< 1)" if options[:key_length] < 1
    raise ArgumentError, "key is too long for hash function" if options[:key_length]/8 > ((2**32 - 1) * options[:hash_function].size)
    raise ArgumentError, "iterations can't be less than 1" if options[:iterations] < 1
  end

  def self.prf(options, data)
    OpenSSL::HMAC.digest(options[:hash_function], options[:password], data)
  end

  # this is a translation of the helper function "F" defined in the spec
  def self.calculate_block(options, block_num)
    # u_1:
    u = prf(options, options[:salt]+[block_num].pack("N"))
    ret = u
    # u_2 through u_c:
    2.upto(options[:iterations]) do
      # calculate u_n
      u = prf(options, u)
      # xor it with the previous results
      ret = ret^u
    end
    ret
  end

  # the bit that actually does the calculating
  def self.calculate!(options)
    # how many blocks we'll need to calculate (the last may be truncated)
    blocks_needed = (options[:key_length].to_f / options[:hash_function].size).ceil
    # reset
    value = ""
    # main block-calculating loop:
    1.upto(blocks_needed) do |block_num|
     value << calculate_block(options,block_num)
    end
    # truncate to desired length:
    value = value.slice(0,options[:key_length]).unpack("H*").first
    value
  end

end

class String
  if RUBY_VERSION >= "1.9"
    def xor_impl(other)
      result = "".encode("ASCII-8BIT")
      o_bytes = other.bytes.to_a
      bytes.each_with_index do |c, i|
        result << (c ^ o_bytes[i])
      end
      result
    end
  else
    def xor_impl(other)
      result = (0..length-1).collect { |i| self[i] ^ other[i] }
      result.pack("C*")
    end
  end

  private :xor_impl

  def ^(other)
    raise ArgumentError, "Can't bitwise-XOR a String with a non-String" \
      unless other.kind_of? String
    raise ArgumentError, "Can't bitwise-XOR strings of different length" \
      unless length == other.length

    xor_impl(other)
  end
end
