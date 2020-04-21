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

  test "Server Check" do
    # Initialize some values
    num_supers = 16;
    {_ignore, server} = GenServer.start_link(Server, [num_supers]);

    # Check the masks are generated as expected
    width_16    = 1;
    expected_16 = Enum.reduce(Enum.to_list(0..15), [], fn num, acc ->
      str = String.pad_leading(Integer.to_string(num, 16), width_16, "0");
      [str | acc]
    end);
    [ width, masks ] = Server.get_masks(16);
    assert width == width_16;
    assert masks == expected_16;
    IO.puts("Mask Check -- Test Value 16 Passed");

    width_256    = 2;
    expected_256 = Enum.reduce(Enum.to_list(0..255), [], fn num, acc ->
      str = String.pad_leading(Integer.to_string(num, 16), width_256, "0");
      [str | acc]
    end);
    [ width, masks ] = Server.get_masks(256);
    assert width_256 == width;
    assert expected_256 == masks;
    IO.puts("Mask Check -- Test Value 256 Passed");

    width_4096    = 3;
    expected_4096 = Enum.reduce(Enum.to_list(0..4095), [], fn num, acc ->
      str = String.pad_leading(Integer.to_string(num, 16), width_4096, "0");
      [str | acc]
    end);
    [ width, masks ] = Server.get_masks(4096);
    assert width_4096 == width;
    assert expected_4096 == masks;
    IO.puts("Mask Check -- Test Value 4096 Passed");

    # User Registration Positive Check
    new_name = "Tommy";
    result = GenServer.call(server, {:register, new_name});
    assert result == :ok;
    new_name = "NotTommy";
    result = GenServer.call(server, {:register, new_name});
    assert result == :ok;
    IO.puts("Regisration Check -- Positive Passed");

    # User Registration Negative Check
    new_name = "Tommy";
    result = GenServer.call(server, {:register, new_name});
    assert result == :name_claimed;
    new_name = "NotTommy";
    result = GenServer.call(server, {:register, new_name});
    assert result == :name_claimed;
    IO.puts("Regisration Check -- Negative Passed");

    # User Log In Positive Check
    result = GenServer.call(server, {:join, "Tommy"});
    assert Map.get(result, :contacts) == [];
    assert Map.get(result, :super) != nil;
    assert Map.get(result, :token) != nil;
    result = GenServer.call(server, {:join, "NotTommy"});
    assert Map.get(result, :contacts) == [];
    assert Map.get(result, :super) != nil;
    assert Map.get(result, :token) != nil;
    IO.puts("Log In Check -- Positive Passed");

    # User Log In Negative Check
    result = GenServer.call(server, {:join, "DefinitelyNotTommy"});
    assert result == :not_registered;
    result = GenServer.call(server, {:join, "AlsoDefinitelyNotTommy"});
    assert result == :not_registered;
    IO.puts("Log In Check -- Negative Passed");

    # Update Contacts Positive Check
    info = GenServer.call(server, {:join, "Tommy"});
    result = GenServer.call(server, {:update, "Tommy", ["NotTommy"], Map.get(info, :token)});
    assert result == :ok;
    info = GenServer.call(server, {:join, "NotTommy"});
    result = GenServer.call(server, {:update, "NotTommy", ["Tommy"], Map.get(info, :token)});
    assert result == :ok;
    IO.puts("Update Contacts Check -- Positive Passed");

    # Update Contacts Negative Check
    [_public, private] = Server.get_keys();
    new_pid   = spawn(fn -> :ok end);
    bad_token = Signature.sign(private, new_pid)
    result = GenServer.call(server, {:update, "OtherTommy", ["Tommy"], bad_token});
    assert result == :bad_token;
    IO.puts("Update Contacts Check -- Negative Passed");

  end

end
