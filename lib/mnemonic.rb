require 'pbkdf2'

class Mnemonic
  VERSION = "0.0.1"
  def self.to_mnemonic(options)
    options ||= {}
    bits = options[:bits] || 128
    unless options[:entropy].nil?
      raise ArgumentError, "Entropy is empty" if options[:entropy] == ""
      entropy_bytes = [options[:entropy]].pack("H*")
    else
      entropy_bytes = OpenSSL::Random.pseudo_bytes(bits/8)
    end
    entropy_binary = entropy_bytes.unpack("B*").first
    seed_binary = entropy_binary + checksum(entropy_binary)
    words_array = File.readlines("words/english.txt").map(&:strip)
    seed_binary.chars.each_slice(11).map(&:join).map{|item| item.to_i(2)}.map {|i| words_array[i]}.join(" ")
  end

  def self.to_entropy(options)
    options ||= {}
    raise ArgumentError, "Mnemonic not set" if options[:mnemonic].nil?
    raise ArgumentError, "Mnemonic is empty" if options[:mnemonic] == ""
    words_array = File.readlines("words/english.txt").map(&:strip)
    mnemonic_array = options[:mnemonic].split(" ").map do |word|
      word_index = words_array.index(word)
      raise IndexError, "Word not found in words list" if word_index.nil?
      word_index.to_s(2).rjust(11,"0")
    end
    mnemonic_binary_with_checksum = mnemonic_array.join.to_s
    entropy_binary = mnemonic_binary_with_checksum.slice(0,mnemonic_binary_with_checksum.length*32/33)
    checksum_bits = mnemonic_binary_with_checksum.slice(-(entropy_binary.length/32),(entropy_binary.length/32))
    if checksum(entropy_binary) == checksum_bits
      return [entropy_binary].pack("B*").unpack("H*").first
    else
      raise SecurityError, "Checksum mismatch, invalid mnemonic"
    end
  end

  def self.checksum(entropy_binary)
    sha256hash = OpenSSL::Digest::SHA256.hexdigest([entropy_binary].pack("B*"))
    sha256hash_binary = [sha256hash].pack("H*").unpack("B*").first
    binary_checksum = sha256hash_binary.slice(0,(entropy_binary.length/32))
  end

  def self.to_seed(options)
    raise ArgumentError, "Mnemonic not set" if options[:mnemonic].nil?
    PBKDF2.hex_string(password: options[:mnemonic], salt: "mnemonic#{options[:password]}", iterations: 2048, hash_function: OpenSSL::Digest::SHA512, key_length: 512)
  end

end
