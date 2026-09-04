# frozen_string_literal: true

# test-suite/ruby/narrowing_buggy.rb — partial nil guards (bead D4).
# Every function below keeps falling through after a nil guard whose branch
# does not exit, so the guarded object can still be nil at the call site.
# Expected: ruby.narrowing.partial_nil_guard findings (buggy >= 1).

require 'logger'

LOGGER = Logger.new($stdout)

# Case 1: `if obj.nil?` branch only logs — fallthrough dereference.
def render_user(user)
  if user.nil?
    LOGGER.warn('missing user, rendering default')
  end
  user.profile.name
end

# Case 2: bare `unless obj` truthiness guard that does not exit.
def charge_card(account)
  unless account
    LOGGER.info('no account supplied')
  end
  account.charge!(19.99)
end

# Case 3: modifier-form partial guard.
def touch_session(session)
  LOGGER.debug('session missing') if session.nil?
  session.touch!
end

# Case 4: instance variable guarded by name.
def load_settings
  if @config.nil?
    LOGGER.warn('config missing, using defaults')
  end
  @config.fetch!(:pool_size)
end
