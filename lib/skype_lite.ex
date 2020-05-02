defmodule SkypeLite do
  use Application
  @moduledoc """
  """

  @doc """
    Top-level function, called with 'mix run'.
  """
  def start(_type, _args) do
    # IO.inspect("Starting!");
    # {num_nodes, _} = Enum.at(System.argv(),0) |> Integer.parse
    # {num_reqs, _}  = Enum.at(System.argv(),1) |> Integer.parse

    # IO.puts("Ready to be run via SkypeLite.run()");
    # _ret = :observer.start;

    metrics = [
      "Messages"
    ]

    Metrics.init(metrics);
    run();
    Metrics.fetch_metrics(metrics);

    {:ok, self()}
  end

  @doc """
    Helper function to start up the simulation.
  """
  def run(sim_run_time \\ 30, lookups_per_client \\ 1024, num_clients \\ 10_000, num_super_nodes \\ 16)  do
    #Create a Dynamic Supervisor to track the children
    supers            = [{DynamicSupervisor, strategy: :one_for_one, name: SkypeLite.DynamicSupervisor}]
    _my_super         = Supervisor.start_link(supers, strategy: :one_for_one)
    {_ignore, sim}    = DynamicSupervisor.start_child(SkypeLite.DynamicSupervisor,{Simulation, [num_clients, num_super_nodes]});

    # Start the simulation and have it run for setup time + run time seconds
    GenServer.call(sim, {:start, sim_run_time, lookups_per_client}, :infinity)
    {:ok, sim}
  end
end

defmodule Metrics do
  def init(metrics) do
    Enum.map(metrics, fn met ->
      :ets.new(String.to_atom(met), [:set, :public, :named_table]);
    end)
  end

  def increment_counter(table, value, delta) do
    :ets.update_counter(String.to_atom(table), value, delta, {1,0});
  end

  def fetch_metrics(metrics) do
    Enum.map(metrics, fn met->
      result = :ets.match(String.to_atom(met), :"$1")
      IO.inspect(result);
    end)
  end
end

defmodule Signature do
  @moduledoc """
    Encapuslates public crypto functions and helper functions for ease of use.
  """

  @doc """
    Compare the two input PIDs to determine if they're equivalent.  Handles
    types of pid() and string.
  """
  def compare_pid(target, user) do
    # Determine if we need to do some input processing before comparing.
    cond do
      # Same types, jsut compare
      (String.valid?(user) and String.valid?(target)) or (is_pid(user) and is_pid(target)) ->
        target == user;
      # Mis-match, do some string manipulation
      is_pid(user) and String.valid?(target) ->
        temp = "#{inspect user}";
        "#{inspect target}" == "#{inspect temp}";
      String.valid?(user) and is_pid(target) ->
        temp = "#{inspect target}";
        "#{inspect target}" == "#{inspect temp}";
      # Default case, compare always fails
      true ->
        false
    end
  end

  @doc """
    Retrieve the top-level server public key from disk.  This could be replaced
    by any other pre-shared location.
  """
  def get_public_key() do
    {:ok, pub_pem}  = File.read("./keys/public_key.pem")
    [pub_pem_entry | _ ]  = :public_key.pem_decode(pub_pem)
    # Assuming first entry is the key you want (or only one key)
    public_key  = :public_key.pem_entry_decode(pub_pem_entry)
    public_key
  end

  @doc """
    Sign the given username + PID pair with the key.  Has built-in expiration time
    to force re-authentication and prevent replay attacks.
  """
  def sign(private, user, name, ttl \\ 30, scale \\ :second) do
    if private != nil and user != nil and name != nil  do
      # Get the important time information
      time    = Time.utc_now();
      expires = Time.to_string(Time.add(time,ttl,scale));
      # Convert the data to strings for signing
      token   = "#{inspect user}<|>#{name}<|>#{expires}";
      # Sign the data
      text = :public_key.encrypt_private(token, private, []);
      text
    else
      :bad_input
    end
  end

  @doc """
    Verifies that the signed token contains the given username + PID pair and that
    it has not expired.
  """
  def check(public, signed, user_pid, user_name) do
    if public != nil and signed != nil and user_pid != nil and user_name != nil do
      # Decrypt the data using the public key
      data = :public_key.decrypt_public(signed, public, []);
      # Did the decryption result in valid data?
      if String.valid?(data) and String.contains?(data, "<|>") do
        # Split our string
        [target_pid, target_name, expires] = String.split(data, "<|>");
        {_, check_time}   = Time.from_iso8601(expires);
        # Has the data expired?
        time_diff = Time.compare(Time.utc_now(),check_time);
        cond do
          compare_pid(target_pid, user_pid) and time_diff == :lt and target_name == user_name ->
            :ok
          time_diff != :lt ->
            :expired
          not compare_pid(target_pid, user_pid) ->
            :wrong_pid
          target_name != user_name ->
            :wrong_name
          true ->
            :internal_error
        end
      else
        :bad_data
      end
    else
      :bad_input
    end
  end

end


defmodule Simulation do
  use GenServer
  @moduledoc """
    This simulation module spawns all of the processes needed to run the system, and directs client
    behavior to exercise the network.
  """

  def start_link(_state) do
    # [ Clients, Super Nodes ]
    GenServer.start_link(__MODULE__, [1024, 16])
  end

  @impl true
  def init(state) do
    {:ok, state}
  end

  @doc """
    Start the required super node children.
  """
  def start_children(state) do
    # Get the information
    clis         = Enum.to_list(0..(Enum.at(state,0)-1));
    cli_to_super = Enum.at(state,1);

    # Make sure we have the login server up first
    {_ignore, serv} = GenServer.start_link(Server, [cli_to_super], name: :SkypeLiteServer);

    # Spin up the clients and point them to their login server
    [ clients, pid_map ] = Enum.reduce(clis, [[], Map.new()], fn _id, acc ->
      clis        = Enum.at(acc, 0);
      pid_to_name = Enum.at(acc, 1);

      # Spawn the processes with a random ID
      id = Integer.to_string(Enum.random(0..10_000_000_000));
      {_ignore, cli} = GenServer.start_link(Client, [id]);

      [ [cli | clis], Map.put(pid_to_name, cli, id) ]
    end)

    # Return the PIDs
    [ serv, clients , pid_map]
  end

  @doc """
    Helper function to get a random subset of a specified length
  """
  def get_rand_set(pool, current, length) do
    if length(current) == length or length(pool) == 0 do
      current
    else
      choice   = Enum.random(pool);
      new_cur  = [choice | current];
      new_pool = pool -- [choice];
      get_rand_set(new_pool, new_cur, length)
    end
  end

  @doc """
    Called when the simulation is supposed to start.  If called with timeout = infinity,
    the simulation will run the specified amount of time.
  """

  @impl true
  def handle_call({:start, time, num_targets}, _from, state) do
    [top_server, clients, pid_map]  = start_children(state)
    cli_mean_delay = 15;
    cli_sd_delay   = 5;

    # Tell the 'clients' where to log in
    Enum.map(clients, fn cli ->
      GenServer.cast(cli, {:join, top_server});
    end)

    # Send the clients a list of other people to contact
    Enum.map(clients, fn cli ->
      others  = get_rand_set(clients -- [cli], [], num_targets);
      targets = Enum.reduce(others, [], fn target, acc ->
        [Map.get(pid_map, target) | acc]
      end)
      GenServer.cast(cli, {:lookup, targets, cli_mean_delay, cli_sd_delay});
    end)

    # Sleep for a while to let the simulation run.
    Process.sleep(time*1000);

    {:reply, "Done", [top_server, clients]}
  end
end


defmodule Server do
  use GenServer
  @moduledoc """
    This is the top-level server.  All clients are required to sign-in/register
    with this server before they are able to use any other actions the system provides.
  """
  @doc """
    Called when fault recovery action is taken.
  """
  def start_link(_state) do
    num_supers = 16;
    server_params = [num_supers];
    GenServer.start_link(__MODULE__, server_params);
  end

  @doc """
    Helper function to process public/private keys.
  """
  def get_key(name) do
    {:ok, pem} = File.read("./keys/" <> name);
    [pem_entry | _ ] = :public_key.pem_decode(pem);
    key = :public_key.pem_entry_decode(pem_entry);
    key
  end
  @doc """
    Retreives the public/private keypair form the local disk.
  """
  def get_keys() do
    public_key = get_key("public_key.pem");
    private_key = get_key("private_key.pem");
    [public_key, private_key]
  end

  @doc """
    Creates bitmasks used to spread the clients many super nodes.

    Masks are string representations of hex numbers, which are compared to the
    top n-bits of the hashed client name.

    NOTE: Inputs should be in powers of the provided.

    Example:
      16 super nodes
      width = 1 (16 machines can be represented in a single hex character "0" -> "F")
      masks = [ "0", "1", "2", ..., "F" ]
  """
  def get_masks(num, base \\ 16) do
    # Should only be using power-of-base numbers, but the math is inexact
    width = (:math.log2(num) / :math.log2(base)) |> Kernel.ceil;
    # IO.inspect(["BITS: ", num_bits])
    nums     = Enum.to_list(0..num-1);
    masks    = Enum.reduce(nums, [], fn id, acc ->
      # Make sure each has a standardized width (i.e. "1" -> "001" if width = 3)
      mask = String.pad_leading(Integer.to_string(id, base), width, "0");
      [ mask | acc ]
    end)
    [ width, masks ]
  end

  @doc """
    Generates a pseudo-random string for naming the super nodes.
  """
  def random_string() do
    random_base_64 = :random.uniform(1_073_741_824) |> Integer.to_string |> Base.encode64;
    hash = :crypto.hash(:md5, random_base_64) |> Base.encode16();
    hash
  end

  @doc """
    Generates log-in information for a super node.
  """
  def get_super_info() do
    my_name = random_string() <> random_string();
    my_pass = random_string() <> random_string() <> random_string() <> random_string();
    m = Map.new([{:name, my_name}, {:password, my_pass}]);
    m
  end

  @doc """
    Coordinates the intialization of the top-level server and the super nodes
    underneath it.
  """
  @impl true
  def init(s) do
    state = Map.new([{:num_supers, Enum.at(s,0)}]);
    [public, private] = get_keys();

    # Get info
    num_supers  = Map.get(state, :num_supers, 16);

    # Set up the masks
    [ mask_width , masks ] = get_masks(num_supers);

    # Spin up the super nodes
    supers = Enum.reduce(masks, Map.new(), fn mask, acc ->
      {_ignore, spr}    = GenServer.start_link(Super, [Map.new()]);
      Map.put(acc, mask, spr);
    end);

    # Create a database for the contact list.  Set = unique keys,
    # Private = only this process can access
    users = :ets.new(:contact_list, [:set, :private]);


    # Distribute the map so super nodes who to contact, and give them registration info
    Enum.map(Map.values(supers), fn target ->
      # Timeout every 30 minutes
      inputs = get_super_info();
      token = Signature.sign(private, target, Map.get(inputs, :name), 1800, :second);
      with_width  = Map.put(inputs, :mask_width, mask_width);
      with_supers = Map.put(with_width, :supers, supers);
      with_token  = Map.put(with_supers, :token, token);
      GenServer.cast(target, {:map, with_token});
    end)

    new_data    = Map.new([{:mask_width, mask_width},{:supers, supers}, {:users, users}, {:public, public}, {:private, private}]);
    updated_map = Map.merge(state, new_data);

    {:ok, updated_map}
  end

  # @doc """
  #   Supply a downed super node with the needed information.
  # """
  # def handle_call({:recover, name, token}, from, state) do
  #   super_public_key = Map.get(state, :super_key, get_key("public_super.pem"));

  #   if Signature.check(super_public_key, token, elem(from,0), name) == :ok do
  #     # Get the required information
  #     mask_width = Map.get(state, :mask_width);
  #     supers     = Map.get(state, :supers);
  #     private    = Map.get(state, :private);

  #     [new_supers, _ignore] = Enum.reduce(Map.to_list(supers), [Map.new(), Map.new()], fn pair, acc ->
  #       [my_map, added] = acc;
  #       {key, value} = pair;
  #       if Process.alive?(value) or Map.get(added, elem(from,0)) != nil do
  #         [Map.put(my_map, key, value), Map.put(added, value, 0)]
  #       else
  #         [Map.put(my_map, key, elem(from,0)), Map.put(added, elem(from,0), 0)]
  #       end
  #     end)

  #     # Generate new user/pass + token
  #     inputs = get_super_info();
  #     token = Signature.sign(private, elem(from,0), Map.get(inputs, :name), 1800, :second);
  #     # Package it up
  #     with_width  = Map.put(inputs, :mask_width, mask_width);
  #     with_supers = Map.put(with_width, :supers, new_supers);
  #     with_token  = Map.put(with_supers, :token, token);
  #     s = Map.put(state, :super_key, super_public_key);
  #     {:reply, with_token, Map.put(s, :supers, new_supers)}
  #   else
  #     {:reply, :bad_token, state}
  #   end
  # end

  @doc """
    Processes the given name to get the section of hex bits used to match against
    a super node code.

    Example:
      "example" => "1A79A4D60DE6718E8E5B326E338AE533" => "1A"
  """
  def get_hash(width, name, base \\ 16) do
    # Get the hash-based information
    hash = :crypto.hash(:md5, name);
    cond do
      base == 2 ->
        String.slice(Base2.encode2(hash), 0..(width-1))
      base == 16 ->
        String.slice(Base.encode16(hash), 0..(width-1))
    end
  end

  @doc """
    Handles the user registration process.
  """
  @impl true
  def handle_call({:register, name}, _from, state) do
    users = Map.get(state, :users);

    # Init the user's contact list to be empty
    result = :ets.insert_new(users, {String.to_atom(name), []})

    # Is there already a user with this name?
    if result != false do
      {:reply, :ok, state}
    else
      {:reply, :name_claimed, state}
    end
  end

  @doc """
    Handles a client's attempt to log in.
  """
  @impl true
  def handle_call({:join, name}, from, state) do
    supers     = Map.get(state, :supers);
    users      = Map.get(state, :users);
    mask_width = Map.get(state, :mask_width);

    # Get the client information
    match = :ets.lookup(users, String.to_atom(name));

    if match != [] do
      # Hash the name to determine who to match it with
      hash_match = get_hash(mask_width, name);
      # Look up the corresponding super node
      matching_super = Map.get(supers, hash_match);
      # Strip away the wrapping structures
      contacts = elem(Enum.at(match,0),1);
      # Create a token for the user
      sending_pid = elem(from,0);
      token = Signature.sign(Map.get(state,:private), sending_pid, name)

      {:reply, Map.new([{:super, matching_super}, {:contacts, contacts}, {:token, token}]), state}
    else
      {:reply, :not_registered, state}
    end
  end

  @doc """
    Updates a user's contact list.
  """
  @impl true
  def handle_call({:update, name, list, token}, from, state) do
    users       = Map.get(state, :users);
    sending_pid = elem(from,0);
    result = Signature.check(Map.get(state, :public), token, sending_pid, name);
    if result == :ok do
      # Update the client information
      :ets.insert(users, {String.to_atom(name), list});

      {:reply, :ok, state}
    else
      {:reply, :bad_token, state}
    end
  end
end


defmodule Super do
  use GenServer
  @moduledoc """
    Super nodes superimpose hierarchy onto an otherwise P2P network.  They are responsible
    mapping their client PID/IP to their user name.
  """

  @doc """
    This is called after a fail is detected, and will call subsequently call the init() function.
  """
  def start_link(_state) do
    GenServer.start_link(__MODULE__, [Map.new()])
  end

  @doc """
    Retreives the public/private keypair form the local disk.
  """
  def get_keys() do
    {:ok, priv_pem} = File.read("./keys/private_super.pem")
    {:ok, pub_pem}  = File.read("./keys/public_super.pem")
    [priv_pem_entry | _ignore ] = :public_key.pem_decode(priv_pem)
    [pub_pem_entry | _ignore ]  = :public_key.pem_decode(pub_pem)
    # Assuming first entry is the key you want (or only one key)
    private_key = :public_key.pem_entry_decode(priv_pem_entry)
    public_key  = :public_key.pem_entry_decode(pub_pem_entry)
    # text = :public_key.encrypt_public("plaintext", public_key, [])
    [public_key, private_key]
  end

  @doc """
    No initializations can be done during spawn time.
  """
  @impl true
  def init(state) do
    # IO.inspect(["init", state]);
    # IO.inspect(state);
    {:ok, state}
  end

  @doc """
    This function is required to be handled before normal operations can commence.  This
    shall be called by the top-level server to inform the super node of the other supers.
  """
  @impl true
  def handle_cast({:map, values}, state) do
    # Inputs packaged into Map already, just confirm that the token is valid before updating
    token = Map.get(values, :token);
    name  = Map.get(values, :name);
    pub = Signature.get_public_key();
    cond do
      Signature.check(pub, token, self(), name) == :ok ->
        new_values = Map.put(values,:public, pub);
        {:noreply, new_values}
      true ->
        {:noreply, state}
    end
  end

  @doc """
    Helper function to avoid code replication. Processes the given name to ge the
    section of hex bits used to match against a super node code.

    Example:
      "example" => "1A79A4D60DE6718E8E5B326E338AE533" => "1A"
  """
  def get_hash(width, name, base \\ 16) do
    # Get the hash-based information
    hash = :crypto.hash(:md5, name);
    cond do
      base == 2 ->
        String.slice(Base2.encode2(hash), 0..(width-1))
      base == 16 ->
        String.slice(Base.encode16(hash), 0..(width-1))
    end
  end

  @impl true
  def handle_info(_msg, state) do
    # {req, resp} = msg;
    # IO.inspect(["HANDLE INFO", self(), req, resp]);

    {:noreply, state}
  end

  @doc """
    This is called after a client has successfully signed in to top-level server. Clients
    using this function are registered to be found by others in the network.
  """
  @impl true
  def handle_call({:join, name, token}, from, state) do
    public_key = Map.get(state, :public);
    user_pid   = elem(from, 0);

    if Signature.check(public_key, token, user_pid, name) == :ok do
      supers     = Map.get(state, :supers);
      my_names   = Map.get(state, :names, Map.new());
      mask_width = Map.get(state, :mask_width);
      _my_token   = Map.get(state, :token);

      # Get the hash-based information
      hash_match = get_hash(mask_width, name);
      contact_point = Map.get(supers, hash_match);

      # We're only accepting the clients for our list.
      if contact_point == self() do
        # Add a new entry for the client. "from" has extra data, just strip the PID
        updated_names = Map.put(my_names, name, user_pid);
        updated_state = Map.put(state, :names, updated_names);
        # IO.inspect(["JOINED at Super Node", self(), updated_map]);
        {:reply, :ok, updated_state}
      else
        {:reply, :out_of_scope, state}
      end
    else
      {:reply, :bad_token, state}
    end
  end


  @doc """
    This is called when a client is logging off of the network (no longer avaialble).
  """
  @impl true
  def handle_call({:leave, name, token}, from, state) do
    public_key = Map.get(state, :public);
    user_pid   = elem(from, 0);

    if Signature.check(public_key, token, user_pid, name) == :ok do
      supers     = Map.get(state, :supers);
      my_names   = Map.get(state, :names, Map.new());
      mask_width = Map.get(state, :mask_width);

      # Get the hash-based information
      hash_match = get_hash(mask_width, name);
      contact_point = Map.get(supers, hash_match);

      # Are we in charge of this client? Make sure to check the client name against requester
      same_person = Map.get(my_names, name) == elem(from, 0);
      if contact_point == self() && same_person do
        new_names = Map.delete(my_names, name);
        new_state = Map.put(state, :names, new_names);
        {:reply, :ok, new_state}
      else
        {:reply, :invalid_request, state}
      end
    else
      {:reply, :bad_token, state}
    end
  end

  @doc """
    Used to search for a target client. Returns a PID/IP if found, otherwise nil.
  """
  @impl true
  def handle_call({:lookup, target, name, token}, from, state) do
    public_key = Map.get(state, :public);
    user_pid   = elem(from, 0);

    token_res = Signature.check(public_key, token, user_pid, name);

    if token_res == :ok do
      supers     = Map.get(state, :supers);
      my_names   = Map.get(state, :names, Map.new());
      mask_width = Map.get(state, :mask_width);
      my_token   = Map.get(state, :token);
      my_name    = Map.get(state, :name);

      # IO.inspect(["LOOKUP @", self(), target]);

      # Hash the name to determine which supervisor to contact
      hash_match = get_hash(mask_width, target);

      # Figure out who to talk to
      contact_point = Map.get(supers, hash_match);

      cond do
        contact_point == self() ->
          # Attempt local lookup
          pid = Map.get(my_names, target, nil);
          {:reply, pid, state}

        contact_point != nil ->
          # Attempt remote query
          # Generate a psuedo-random timeout value to reduce call->call collisions
          rand_timeout = :rand.uniform(1500) + 10;
          try do
            reponse = GenServer.call(contact_point, {:lookup, target, my_name, my_token}, rand_timeout);
            {:reply, reponse, state}
          catch
            :exit, {:timeout, _info} ->
              {:reply, :timeout, state}
            end

        true ->
          # Attempting to access a non-mapped server
          {:reply, :no_matching_super, state}
      end
    else
      {:reply, token_res, state}
    end
  end

end


defmodule Client do
  use GenServer
  @moduledoc """
    Used by the clients in the network.  Currently controlled by the simulation to
    interact with the system.
  """

  def start_link(_state) do
    GenServer.start_link(__MODULE__, [])
  end

  @impl true
  def init(state) do
    # IO.inspect(state);
    {:ok, state}
  end

  @doc """
    Get a random delay in ms, governed by the normal distribution.
  """
  def get_rand_delay(mean, sd) do
    rand_delay = Statistics.Distributions.Normal.rand(mean,sd) |> trunc;
    if rand_delay < 0 do
      0
    else
      rand_delay * 1000
    end
  end

  @doc """
    Attempts to find the given target, delayed by a random time (using mean + standard deviation)
  """
  @impl true
  def handle_cast({:lookup, targets, mean, sd}, state) do
    # IO.puts("lookup");
    my_name = Enum.at(state, 0);
    my_super = Enum.at(state, 1);
    my_token = Enum.at(state, 3);

    if length(targets) > 0 do
      target = Enum.at(targets, 0);
      # Do a lookup
      try do
        Metrics.increment_counter("Messages", "Sent", 1);
        repsonse = GenServer.call(my_super, {:lookup, target, my_name, my_token}, 3000);
        # IO.puts("message");
        cond do
          repsonse == :expired ->
            Metrics.increment_counter("Messages", "Expired", 1);
            # IO.puts("TOKEN EXPIRED");
            # Refresh the token
            resp = GenServer.call(:SkypeLiteServer, {:join, my_name});
            my_token = Map.get(resp, :token);
            # Sleep to simulate random access
            delay = get_rand_delay(mean, sd);
            Process.sleep(delay);
            # Continue the process
            GenServer.cast(self(),{:lookup, targets, mean, sd});
            {:noreply, List.replace_at(state, 3, my_token)}

          # Retry the lookup
          repsonse == :timeout  or repsonse == nil->
            if repsonse == :timeout do
              Metrics.increment_counter("Messages", "Timeout", 1);
            else
              Metrics.increment_counter("Messages", "NotLoggedIn", 1);
            end
            # IO.puts("TIMEOUT OR NIL");
            # Sleep to simulate random access
            delay = get_rand_delay(mean, sd);
            Process.sleep(delay);
            # Continue the process
            GenServer.cast(self(),{:lookup, targets, mean, sd});
            {:noreply, state}

          # Sucessful
          is_pid(repsonse) ->
            Metrics.increment_counter("Messages", "Successful", 1);
            # IO.puts("GOOD MESSAGE");
            # Sleep to simulate random access
            delay = get_rand_delay(mean, sd);
            Process.sleep(delay);
            # Continue the process with the rest of the targets
            GenServer.cast(self(),{:lookup, targets -- [target], mean, sd})
            {:noreply, state}

          true ->
            # Catch all
            Metrics.increment_counter("Messages", "OtherError", 1);
            IO.inspect([self(), repsonse]);
            {:noreply, state}
        end
      catch
        # My call timed out
        :exit, {:timeout, _info} ->
          Metrics.increment_counter("Messages", "Timeout", 1);
          # Sleep to simulate random access
          delay = get_rand_delay(mean, sd);
          Process.sleep(delay);
          # Continue the process
          GenServer.cast(self(),{:lookup, targets, mean, sd});
          {:noreply, state}
      end
    else
      {:noreply, state}
    end
  end

  @doc """
    Used to log in to the system.
  """
  @impl true
  def handle_cast({:join, server}, state) do
    # IO.puts("join");
    my_name  = Enum.at(state, 0);

    # Spread out the :join requests
    Process.sleep(get_rand_delay(3, 0.5));

    # IO.puts("Starting request");

    try do
      # Register with the server first!
      _result = GenServer.call(server, {:register, my_name});

      # Contact the server for my super node
      response = GenServer.call(server, {:join, my_name});

      if response != :not_registered do
        my_super = Map.get(response, :super);
        contacts = Map.get(response, :contacts);
        my_token = Map.get(response, :token);
        # IO.inspect(response);

        cond do
          my_super != nil ->
            # Join the super node.  return should be :ok if succeeded
            result = GenServer.call(my_super, {:join, my_name, my_token});
            if result != :ok do
              IO.inspect(["Super join failed", self()]);
            else
              # IO.puts("Successfully joined");
            end
          true ->
            IO.inspect(["Super Lookup Failed.", my_name, self()]);
        end

        new_state = [my_name, my_super, contacts, my_token]

        {:noreply, new_state}
      else
        IO.puts("Client joined but not registered.")

        {:noreply, state}
      end
    catch
      # Retry the join logic if we timeout
      :exit, {:timeout, _info} ->
        IO.puts("RE-TRYING JOIN");
        GenServer.cast(self(), {:join, server})
    end
  end
end
