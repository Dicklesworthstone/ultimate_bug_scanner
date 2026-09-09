defmodule AstRulePackBuggy do
  def test_ast_rules(pid, data) do
    # 1. code-eval-string
    Code.eval_string("1 + 1")
    # 2. code-eval-file
    Code.eval_file("script.exs")
    # 3. system-cmd-shell
    System.cmd("sh", ["-c", "echo 1"])
    # 4. system-shell
    System.shell("echo 1")
    # 5. process-sleep
    Process.sleep(100)
    # 6. io-inspect
    IO.inspect(data)
    # 7. io-puts
    IO.puts("hello")
    # 8. file-rm-rf
    File.rm_rf("/tmp/foo")
    # 9. file-rm-rf-bang
    File.rm_rf!("/tmp/bar")
    # 10. string-to-atom
    String.to_atom("foo")
    # 11. string-to-existing-atom
    String.to_existing_atom("bar")
    # 12. binary-to-term-unsafe
    :erlang.binary_to_term(data)
    # 13. crypto-md5
    :crypto.hash(:md5, data)
    # 14. crypto-sha1
    :crypto.hash(:sha, data)
    # 15. send-unhandled
    send(pid, :hello)
    # 16. spawn-unlinked
    spawn(fn -> :ok end)
    # 17. spawn-link
    spawn_link(fn -> :ok end)
    # 18. jason-decode-bang
    Jason.decode!("{}")
    # 19. poison-decode-bang
    Poison.decode!("{}")
    # 20. repo-query
    Repo.query("SELECT 1")
    # 21. repo-query-bang
    Repo.query!("SELECT 1")
    # 22. kernel-exit
    if false, do: exit(:normal)
    # 23. kernel-throw
    if false, do: throw(:error)
    # 24. process-exit
    Process.exit(pid, :kill)
    # 25. system-halt
    if false, do: System.halt(1)
    # 26. node-spawn
    Node.spawn(:node, fn -> :ok end)
  end
end
