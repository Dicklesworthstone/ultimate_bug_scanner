# frozen_string_literal: false
#
# GH #91 suppression fixture (bead A7) for the Ruby module, twin of
# suppression_buggy.rb: identical buggy code with every ubs:ignore marker
# removed, so a scan of this file must reproduce the native ruby findings
# (eval, single-string system, File.open without close) that the markered
# twin suppresses. The file handle stays outside a block here because the
# ruby lifecycle helper is marker-blind; the markered twin pairs it via
# the block form hosting the formatter-relocated arrangement.

module SuppressionProbe
  SPOOL_PATH = 'spool.txt'

  # Arrangement 1: previous-line marker goes immediately above this finding.
  def self.eval_prev_line(code)
    eval(code)
    code
  end

  # Arrangement 2: trailing marker belongs on this flagged line itself.
  def self.eval_trailing(code)
    eval(code)
    code
  end

  # Arrangement 2b: rule-scoped trailing marker belongs here.
  def self.eval_rule_scoped(code)
    eval(code)
    code
  end

  # Arrangement 3: multi-line statement; marker belongs on the flagged
  # continuation line of that statement.
  def self.system_multiline(cmd)
    outcome =
      system("sh -c \"#{cmd}\"")
    outcome == true
  end

  # Arrangement 4: formatter-relocated marker belongs on the first line
  # inside the block whose opening line is flagged. This twin holds the
  # unpaired assignment the markered twin's block form replaces.
  def self.write_spool
    spool = File.open(SPOOL_PATH, 'w')
    spool.write('spooled')
    spool
  end
end
