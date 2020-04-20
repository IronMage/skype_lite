defmodule SkypeLiteTest do
  use ExUnit.Case

  test "Public/Private Check" do
    # Retrieve Server keys for encryption
    [pub, priv] = Server.get_keys();

    # Positive Result Check
    cipher = Signature.sign(priv, self(), 30, :second);
    result = Signature.check(pub, cipher, self());
    # Should have worked
    assert result == :ok
    IO.puts("Public/Private Check -- Positive Passed.");

    # Timeout Result Check
    cipher = Signature.sign(priv, self(), 0, :second);
    Process.sleep(1);
    result = Signature.check(pub, cipher, self());
    # Expecting an expired
    assert result == :expired
    IO.puts("Public/Private Check -- Timeout Passed.");

    # Wrong User Result Check
    all_pids = Process.list();
    all_but_me = all_pids -- [self()];
    other_user = Enum.random(all_but_me);
    cipher = Signature.sign(priv, other_user, 0, :second);
    Process.sleep(1);
    result = Signature.check(pub, cipher, self());
    # Expecting an expired
    assert result == :wrong_user
    IO.puts("Public/Private Check -- Wrong User Passed.");
  end

  test "Super Node Check" do
 # Spawn some super nodes to work with.
    {_ignore, super1}    = GenServer.start_link(Super, [Map.new()]);
    {_ignore, super2}    = GenServer.start_link(Super, [Map.new()]);
    {_ignore, super3}    = GenServer.start_link(Super, [Map.new()]);
    # Set up the super map to send
    test_name  = "example";
    test_match = Super.get_hash(1, test_name);

    other_name  = "test";
    other_match = Super.get_hash(1, other_name);

    super_map = Map.new([{test_match, super1}, {"Q", super2}, {other_match, super3}]);

    # Send the information
    GenServer.cast(super1, {:map, [1, super_map]});
    GenServer.cast(super2, {:map, [1, super_map]});
    GenServer.cast(super3, {:map, [1, super_map]});
    # Let the messages arrive
    Process.sleep(1);

    # Join Positive Result Check
    result = GenServer.call(super1,{:join, test_name});
    assert result == :ok;
    IO.puts("Join Check -- Positive Passed.");

    # Leave Positive Result Check
    result = GenServer.call(super1,{:leave, test_name});
    assert result == :ok;
    IO.puts("Leave Check -- Positive Passed.");

    # Join Negative Result Check
    result = GenServer.call(super2,{:join, test_name});
    assert result == :out_of_scope;
    IO.puts("Join Check -- Negative Passed.");

    # Leave Negative Result Check
    result = GenServer.call(super2,{:leave, test_name});
    assert result == :invalid_request;
    IO.puts("Leave Check -- Negative Passed.");

    # Lookup Check Setup
    user1_res = GenServer.call(super1,{:join, test_name});
    assert user1_res == :ok;
    user2_res = GenServer.call(super3,{:join, other_name});
    assert user2_res == :ok;

    # Lookup Positive Result Check
    result = GenServer.call(super1, {:lookup, other_name});
    assert Signature.compare_pid(self(), result);
    IO.puts("Lookup Check -- Positive Passed");

    # Lookup No Matching Super Result Check
    result = GenServer.call(super1, {:lookup, "not_listed"});
    assert result == :no_matching_super
    IO.puts("Lookup Check -- No Matching Super Passed");

    # Lookup No Matching User Result Check
    result = GenServer.call(super1, {:lookup, "query"});
    assert result == nil
    IO.puts("Lookup Check -- No Matching User Passed");

  end

end
