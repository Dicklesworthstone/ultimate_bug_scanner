# frozen_string_literal: false
#
# GH #91 suppression fixture (bead A7) for the Ruby module, twin of
# suppression_buggy_nomarkers.rb (identical buggy code, markers removed,
# except where noted: the ruby lifecycle helper is marker-blind, so the
# markered twin pairs the file handle through the block form).
# Every native ruby finding below (eval, single-string system, File.open
# without close) carries an ubs:ignore marker in one of the documented
# arrangements, so scanning this file must report zero findings while the
# nomarkers twin reproduces them.

module SuppressionProbe
  SPOOL_PATH = 'spool.txt'

  # Arrangement 1: previous-line marker. The module count filter is
  # same-line only, so the trailing twin rides along; the postprocess
  # engine (GH #91) covers the previous-line placement.
  def self.eval_prev_line(code)
    # ubs:ignore -- fixture: marker on the line immediately above the finding
    eval(code) # ubs:ignore -- fixture: trailing twin for the module count filter
    code
  end

  # Arrangement 2: trailing marker on the flagged line itself.
  def self.eval_trailing(code)
    eval(code) # ubs:ignore -- fixture: trailing marker
    code
  end

  # Arrangement 2b: rule-scoped trailing marker (ubs:ignore[rule]).
  def self.eval_rule_scoped(code)
    eval(code) # ubs:ignore[rb.eval-exec] -- fixture: rule-scoped trailing marker
    code
  end

  # Arrangement 3: multi-line statement, marker on the flagged
  # continuation line of that statement.
  def self.system_multiline(cmd)
    outcome =
      system("sh -c \"#{cmd}\"") # ubs:ignore -- fixture: marker on a physical line of a multi-line statement
    outcome == true
  end

  # Arrangement 4: formatter-relocated marker on the first line inside
  # the block whose opening line the scanner flags. The nomarkers twin
  # holds the handle outside a block (never closed), which is the finding
  # this arrangement hosts.
  def self.write_spool
    File.open(SPOOL_PATH, 'w') do |spool|
      # ubs:ignore -- fixture: formatter moved the trailing marker inside the block
      spool.write('spooled')
    end
  end
end
