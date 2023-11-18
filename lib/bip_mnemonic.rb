# frozen_string_literal: true

require 'openssl'
require 'pbkdf2'
require 'securerandom'

class BipMnemonic
  VERSION = '0.0.1'

  attr_reader :language

  def initialize(language = 'english')
    @language = language
  end

  def to_mnemonic(entropy: nil, bits: nil)
    entropy_bytes = if entropy.nil? || entropy.empty?
                      generate_random_bytes(bits)
                    else
                      [entropy].pack('H*')
                    end

    mnemonic_from_entropy(entropy_bytes)
  end

  def to_entropy(mnemonic:)
    validate_mnemonic(mnemonic)
    entropy_binary_with_checksum = mnemonic_to_binary(mnemonic)
    entropy_binary = remove_checksum(entropy_binary_with_checksum)
    [entropy_binary].pack('B*').unpack1('H*')
  end

  def to_seed(mnemonic:, salt:)
    validate_mnemonic(mnemonic)
    PBKDF2.hex_string(password: mnemonic, salt: "mnemonic#{salt}", iterations: 2048,
                      hash_function: OpenSSL::Digest::SHA512, key_length: 512)
  end

  private

  def validate_mnemonic(mnemonic)
    raise ArgumentError, 'Mnemonic not set' unless mnemonic
    raise ArgumentError, 'Mnemonic is empty' if mnemonic.empty?
  end

  def generate_random_bytes(bits)
    SecureRandom.random_bytes(bits / 8)
  end

  def mnemonic_from_entropy(entropy_bytes)
    entropy_binary = entropy_bytes.unpack1('B*')
    seed_binary = entropy_binary + checksum(entropy_binary)
    seed_binary.chars.each_slice(11).map(&:join).map { |binary| words[binary.to_i(2)] }.join(' ')
  end

  def checksum(entropy_binary)
    sha256hash = OpenSSL::Digest::SHA256.digest([entropy_binary].pack('B*'))
    sha256hash_binary = sha256hash.unpack1('B*')
    sha256hash_binary[0, entropy_binary.length / 32]
  end

  def mnemonic_to_binary(mnemonic)
    mnemonic.split(' ').map do |word|
      word_index = words.index(word) or raise IndexError, 'Word not found in words list'
      word_index.to_s(2).rjust(11, '0')
    end.join
  end

  def remove_checksum(binary_with_checksum)
    checksum_length = binary_with_checksum.length / 33
    binary_with_checksum[0...-checksum_length]
  end

  def words
    @words ||= File.readlines("words/#{@language}.txt").map(&:strip)
  end
end
