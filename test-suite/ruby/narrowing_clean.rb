# frozen_string_literal: true

# test-suite/ruby/narrowing_clean.rb — properly handled nil guards (bead D4).
# Expected: zero ruby.narrowing.partial_nil_guard findings (clean == 0).

require 'logger'

LOGGER = Logger.new($stdout)
DEFAULT_USER = Struct.new(:name).new('guest')

# Guard branch exits: fallthrough implies a non-nil object.
def render_user(user)
  if user.nil?
    return DEFAULT_USER.name
  end
  user.profile.name
end

# unless guard raising in the nil branch.
def charge_card(account)
  unless account
    raise ArgumentError, 'account is required'
  end
  account.charge!(19.99)
end

# Safe navigation after a non-exiting guard: no plain dereference.
def label_for(user)
  if user.nil?
    LOGGER.warn('anonymous visitor')
  end
  user&.profile&.label
end

# Reassigned after the guard: later calls belong to the new value.
def next_session(session)
  if session.nil?
    LOGGER.debug('starting fresh session')
  end
  session = Session.new
  session.touch!
end

# Exiting modifier guard.
def touch_session(session)
  return if session.nil?
  session.touch!
end

# Guards never carry across method boundaries.
def rename_user(user)
  user.name = DEFAULT_USER.name
end

# Comments and strings must not create phantom guards.
def documented(user)
  # if user.nil? nothing to see here
  puts 'if user.nil? then skip'
  user.display_name
end
