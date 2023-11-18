# frozen_string_literal: true

require 'simplecov'
SimpleCov.start
Dir[File.join(File.dirname(__FILE__), '..', 'lib', '*.rb')].sort.each { |f| require f }
