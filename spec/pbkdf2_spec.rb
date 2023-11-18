# frozen_string_literal: true

require "#{File.dirname(__FILE__)}/spec_helper.rb"

describe PBKDF2, 'when deriving keys' do
  # Utility method to run PBKDF2 test
  def run_pbkdf2_test(test_case)
    expected_hex = test_case[:expected_hex].gsub(' ', '')
    derived_key = PBKDF2.hex_string({
                                      hash_function: OpenSSL::Digest::SHA1,
                                      iterations: test_case[:iterations],
                                      password: test_case[:password],
                                      salt: test_case[:salt],
                                      key_length: test_case[:key_length]
                                    })
    expect(derived_key).to eq expected_hex
  end

  # Define test cases
  test_cases = [
    {
      iterations: 1,
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      key_length: 128,
      expected_hex: 'cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15'
    },
    {
      iterations: 1,
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      key_length: 256,
      expected_hex: 'cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15 0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37'
    },
    {
      iterations: 2,
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      key_length: 128,
      expected_hex: '01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d'
    },
    {
      iterations: 2,
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      key_length: 256,
      expected_hex: '01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86'
    },
    {
      iterations: 1200,
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      key_length: 128,
      expected_hex: '5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b'
    },
    {
      iterations: 1200,
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      key_length: 256,
      expected_hex: '5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13'
    },
    {
      iterations: 5,
      password: 'password',
      salt: [0x1234567878563412].pack('Q'),
      key_length: 128,
      expected_hex: 'd1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49'
    },
    {
      iterations: 5,
      password: 'password',
      salt: [0x1234567878563412].pack('Q'),
      key_length: 256,
      expected_hex: 'd1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49 3f 98 d2 03 e6 be 49 a6 ad f4 fa 57 4b 6e 64 ee'
    },
    {
      iterations: 1200,
      password: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      salt: 'pass phrase equals block size',
      key_length: 128,
      expected_hex: '13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9'
    },
    {
      iterations: 1200,
      password: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      salt: 'pass phrase equals block size',
      key_length: 256,
      expected_hex: '13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9 c5 ec 59 f1 a4 52 f5 cc 9a d9 40 fe a0 59 8e d1'
    },
    {
      iterations: 1200,
      password: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      salt: 'pass phrase exceeds block size',
      key_length: 128,
      expected_hex: '9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61'
    },
    {
      iterations: 1200,
      password: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      salt: 'pass phrase exceeds block size',
      key_length: 256,
      expected_hex: '9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61 1a 8b 4d 28 26 01 db 3b 36 be 92 46 91 5e c8 2a'
    },
    {
      iterations: 50,
      password: [0xf09d849e].pack('N'),
      salt: 'EXAMPLE.COMpianist',
      key_length: 128,
      expected_hex: '6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39'
    },
    {
      iterations: 50,
      password: [0xf09d849e].pack('N'),
      salt: 'EXAMPLE.COMpianist',
      key_length: 256,
      expected_hex: '6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39 e7 fe 37 a0 c4 1e 02 c2 81 ff 30 69 e1 e9 4f 52'
    }
  ]

  # Run all test cases
  test_cases.each do |test_case|
    it "should match the PBKDF2 output for iteration count #{test_case[:iterations]}" do
      run_pbkdf2_test(test_case)
    end
  end
end
