defmodule SkypeLite do
  use Application
  @moduledoc """
  """

  @doc """
  """
  def start(_type, _args) do
    IO.inspect("Starting!");
    # {num_nodes, _} = Enum.at(System.argv(),0) |> Integer.parse
    # {num_reqs, _}  = Enum.at(System.argv(),1) |> Integer.parse

    #Create a Dynamic Supervisor to track the children
    supers            = [{DynamicSupervisor, strategy: :one_for_one, name: SkypeLite.DynamicSupervisor}]
    _my_super         = Supervisor.start_link(supers, strategy: :one_for_one)
    {_ignore, sim}    = DynamicSupervisor.start_child(SkypeLite.DynamicSupervisor,{Simulation, []});

    GenServer.call(sim, {:start})

    {:ok, sim}
  end
end


defmodule Simulation do
  use GenServer
  @moduledoc """
    This simulation spwans all of the processes needed to run the system, and directs client
    behavior to exercise the network.
  """

  def start_link(_state) do
    # [ Clients, Super Nodes ]
    GenServer.start_link(__MODULE__, [16, 16])
  end

  @impl true
  def init(state) do
    {:ok, state}
  end

  def start_children(state) do
    # Get the information
    clis         = Enum.to_list(0..(Enum.at(state,0)-1));
    cli_to_super = Enum.at(state,1);

    # Make sure we have the login server up first
    {_ignore, serv} = GenServer.start_link(Server, [cli_to_super]);

    # Spin up the clients and point them to their login server
    [ clients, pid_map ] = Enum.reduce(clis, [[], Map.new()], fn _id, acc ->
      clis        = Enum.at(acc, 0);
      pid_to_name = Enum.at(acc, 1);

      # Spawn the processes
      id = Integer.to_string(Enum.random(0..10_000_000_000));
      {_ignore, cli} = GenServer.start_link(Client, [id]);

      [ [cli | clis], Map.put(pid_to_name, cli, id) ]
    end)

    # Return the PIDs
    [ serv, clients , pid_map]
  end

  @impl true
  def handle_call({:start}, _from, state) do 
    [top_server, clients, pid_map]  = start_children(state)

    # IO.inspect([top_server, clients])

    # Tell the 'clients' where to log in
    Enum.map(clients, fn cli ->
      GenServer.cast(cli, {:join, top_server});
    end)

    # Test the lookup function
    test   = Enum.random(clients);
    target = Enum.random(clients -- [test]); 
    GenServer.cast(test, {:lookup, Map.get(pid_map, target)});

    # Needs a better stop condition
    Process.sleep(1000);

    # IO.inspect(["Done"]);
    {:reply, "Done", [top_server, clients]}
  end
end


defmodule Server do
  use GenServer
  @moduledoc """
    This is the top-level server.  All clients are required to sign-in/register 
    with this server before they are able to use any other actions the system provides.
  """

  def start_link(_state) do
    GenServer.start_link(__MODULE__, [:server_nums])
  end

  @doc """
    Creates bitmasks used to spread the clients many super nodes.  

    Masks are string representations of hex numbers, which are compared to the 
    top n-bits of the hashed client name.

    Example:
      16 super nodes
      width = 1 (16 machines can be represented in a single hex character "0" -> "F")
      masks = [ "0", "1", "2", ..., "F" ]
  """
  def get_masks(num) do
    # Should only be using power-of-two numbers
    width = (:math.log2(num) / :math.log2(16)) |> Kernel.ceil;
    # IO.inspect(["BITS: ", num_bits])
    nums     = Enum.to_list(0..num);
    masks    = Enum.reduce(nums, [], fn id, acc ->
      # Make sure each has a standardized width (i.e. "1" -> "001" if width = 3)
      mask = String.pad_leading(Integer.to_string(id, 16), width, "0");
      [ mask | acc ]
    end)
    [ width, masks ]
  end

  @doc """
    Coordinates the intialization of the top-level server and the super nodes
    underneath it.
  """
  @impl true
  def init(state) do
    # IO.inspect(state);

    # Get info
    num_supers  = Enum.at(state,0)-1;

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


    # Distribute the map so super nodes who to contact
    Enum.map(Map.values(supers), fn target ->
      GenServer.cast(target, {:map, [ mask_width, supers ]});
    end)

    new_state = [ mask_width, supers, users ]

    {:ok, new_state}
  end

  @doc """
    Processes the given name to get the section of hex bits used to match against 
    a super node code.

    Example:
      "example" => "1A79A4D60DE6718E8E5B326E338AE533" => "1A"
  """
  def get_hash(state, name) do
    mask_width = Enum.at(state, 0);

    # Get the hash-based information
    hash       = :crypto.hash(:md5, name) |> Base.encode16;
    hash_match = String.slice(hash, 0..(mask_width-1));
    
    hash_match
  end

  @doc """
    Handles the user registration process.
  """
  @impl true
  def handle_call({:register, name}, _from, state) do 
    users = Enum.at(state, 2);


    # Init the user's conact list to be empty
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
  def handle_call({:join, name}, _from, state) do 
    supers     = Enum.at(state,1);
    users      = Enum.at(state,2);

    # Get the client information
    match = :ets.lookup(users, String.to_atom(name));

    if match != [] do
      # Hash the name to determine who to match it with
      hash_match = get_hash(state, name);
      # Look up the corresponding super node
      matching_super = Map.get(supers, hash_match);
      # Strip away the wrapping structures
      contacts = elem(Enum.at(match,0),1);

      {:reply, [ matching_super, contacts ], state}
    else
      {:reply, :not_registered, state}
    end    
  end

  @doc """
    Updates a user's contact list.
  """
  @impl true
  def handle_call({:update, name, list}, _from, state) do 
    users      = Enum.at(state,2);

    # Update the client information
    :ets.insert(users, {String.to_atom(name), list});

    {:reply, :ok, state}
  end
end


defmodule Super do
  use GenServer
  @moduledoc """
    Super nodes superimpose hierarchy onto an otherwise P2P network.  They are responsible 
    mapping their client PID/IP to their user name.
  """

  def start_link(_state) do
    GenServer.start_link(__MODULE__, [:super_nums])
  end

  @doc """
    No initializations can be done during spawn time.
  """
  @impl true
  def init(state) do
    # IO.inspect(state);
    {:ok, state}
  end  

  @doc """
    This function is required to be handled before normal operations can commence.  This
    shall be called by the top-level server to inform the super node of the other supers.
  """
  @impl true
  def handle_cast({:map, [ mask_width, supers ]}, state) do
    # Used for communication between other super nodes
    new_state = [mask_width | [ supers | state ]];

    {:noreply, new_state}
  end

  @doc """
    Helper function to avoid code replication. Processes the given name to ge the 
    section of hex bits used to match against a super node code.

    Example:
      "example" => "1A79A4D60DE6718E8E5B326E338AE533" => "1A"
  """
  def get_hash(state, name) do
    mask_width = Enum.at(state, 0);

    # Get the hash-based information
    hash       = :crypto.hash(:md5, name) |> Base.encode16;
    hash_match = String.slice(hash, 0..(mask_width-1));
    
    hash_match
  end

  @doc """
    This is called after a client has successfully signed in to top-level server. Clients
    using this function are registered to be found by others in the network.
  """
  @impl true
  def handle_call({:join, name}, from, state) do
    supers     = Enum.at(state, 1);
    my_names = Enum.at(state, 2);


    # Get the hash-based information
    hash_match = get_hash(state, name);
    contact_point = Map.get(supers, hash_match);

    # We're only accepting the clients for our list. 
    if contact_point == self() do
      # Add a new entry for the client. "from" has extra data, just strip the PID
      updated_map = Map.put(my_names, name, elem(from, 0));

      # IO.inspect(["JOINED at Super Node", self(), updated_map]);
      {:reply, :ok, List.replace_at(state, 2, updated_map)}
    else
      {:reply, :out_of_scope, state}
    end
  end


  @doc """
    This is called when a client is logging off of the network (no longer avaialble).
  """
  @impl true
  def handle_call({:leave, name}, from, state) do
    supers     = Enum.at(state, 1);
    my_names   = Enum.at(state, 2);

    # Get the hash-based information
    hash_match = get_hash(state, name);
    contact_point = Map.get(supers, hash_match);

    # Are we in charge of this client? Make sure to check the client name against requester
    same_person = Map.get(my_names, name) == elem(from, 0);
    if contact_point == self() && same_person do
      new_map = Map.delete(my_names, name);
      new_state = List.replace_at(state, 2, new_map);
      {:reply, :ok, new_state}
    else
      {:reply, :invalid_request, state}
    end

  end

  @doc """
    Used to search for a target client. Returns a PID/IP if found, otherwise nil.
  """
  @impl true
  def handle_call({:lookup, target}, _from, state) do
    supers     = Enum.at(state, 1);
    my_names   = Enum.at(state, 2);

    # IO.inspect(["LOOKUP @", self(), target]);

    # Hash the name to determine which supervisor to contact
    hash_match = get_hash(state, target);

    # Figure out who to talk to
    contact_point = Map.get(supers, hash_match);

    if ( contact_point != self() )  do
      # Pass on the target
      pid = GenServer.call(contact_point, {:lookup, target});
      # IO.inspect(["RETURNING", pid]);
      {:reply, pid, state}
    else
      # Default the failed lookup to nil
      pid = Map.get(my_names, target, nil);
      # IO.inspect(["RETURNING", pid]);
      {:reply, pid, state}
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
    GenServer.start_link(__MODULE__, [:client_nums])
  end

  @impl true
  def init(state) do
    # IO.inspect(state);
    {:ok, state}
  end

  @doc """
    Used to search for a target client.
  """
  @impl true
  def handle_cast({:lookup, target}, state) do
    my_super = Enum.at(state, 1);

    # Do a lookup
    _pid = GenServer.call(my_super, {:lookup, target});
    # IO.inspect(["CLIENT GOT", pid]);

    {:noreply, state}
  end

  @doc """
    Used to log in to the system.
  """
  @impl true
  def handle_cast({:join, server}, state) do
    my_name  = Enum.at(state, 0);

    # IO.inspect(["Joining server!", server]);

    # Register with the server first!
    _result = GenServer.call(server, {:register, my_name});
    # IO.inspect(["REGISTRATION", result]);

    # Contact the server for my super node
    response = GenServer.call(server, {:join, my_name});

    if response != :not_registered do
      [ my_super, contacts ] = response;
      # IO.inspect(response);

      # Join the super node.  return should be :ok if succeeded
      result = GenServer.call(my_super, {:join, my_name});

      if result != :ok do
        IO.inspect(["Super join failed", self()]);
      end

      new_state = [my_name, my_super, contacts]
      {:noreply, new_state}
    else
      IO.puts("Client joined but not registered.")

      {:noreply, state}
    end
  end
end