defmodule VulnerableApp do
  @moduledoc """
  A vulnerable Elixir application demonstrating common security issues
  """

  # Hardcoded secrets
  @secret_key "super_secret_elixir_key_2023"
  @api_token "elx_1234567890abcdef"
  @database_password "admin123!@#"

  def main do
    IO.puts("=== Vulnerable Elixir Application ===")
    IO.puts("Secret Key: #{@secret_key}")
    
    IO.puts("\n1. Testing atom exhaustion vulnerability...")
    atom_exhaustion_demo()
    
    IO.puts("\n2. Testing code injection...")
    code_injection_demo()
    
    IO.puts("\n3. Testing unsafe deserialization...")
    unsafe_deserialization_demo()
    
    IO.puts("\n4. Testing path traversal...")
    path_traversal_demo()
    
    IO.puts("\n5. Testing weak randomness...")
    weak_randomness_demo()
    
    IO.puts("\n6. Testing information disclosure...")
    information_disclosure_demo()
  end

  def atom_exhaustion_demo do
    IO.write("Enter dynamic atom name: ")
    user_input = IO.read(:stdio, :line) |> String.trim()
    
    # Atom exhaustion vulnerability - converts user input directly to atom
    # This can exhaust the atom table and crash the VM
    dangerous_atom = String.to_atom(user_input)
    IO.puts("Created atom: #{dangerous_atom}")
  rescue
    e -> IO.puts("Atom creation error: #{inspect(e)}")
  end

  def code_injection_demo do
    IO.write("Enter Elixir code to evaluate: ")
    user_code = IO.read(:stdio, :line) |> String.trim()
    
    # Code injection vulnerability - evaluates user input as code
    try do
      {result, _} = Code.eval_string(user_code)
      IO.puts("Code result: #{inspect(result)}")
    rescue
      e -> IO.puts("Code evaluation error: #{inspect(e)}")
    end
  end

  def unsafe_deserialization_demo do
    IO.write("Enter Erlang term to deserialize: ")
    user_input = IO.read(:stdio, :line) |> String.trim()
    
    # Unsafe deserialization - directly deserializes user input
    # This can lead to code execution if malicious terms are provided
    try do
      term = :erlang.binary_to_term(user_input)
      IO.puts("Deserialized term: #{inspect(term)}")
    rescue
      e -> IO.puts("Deserialization error: #{inspect(e)}")
    end
  end

  def path_traversal_demo do
    IO.write("Enter file path to read: ")
    file_path = IO.read(:stdio, :line) |> String.trim()
    
    # Path traversal vulnerability - no validation of file path
    case File.read(file_path) do
      {:ok, content} ->
        content_preview = String.slice(content, 0, 200)
        IO.puts("File content: #{content_preview}...")
      {:error, reason} ->
        IO.puts("File read error: #{reason}")
    end
  end

  def weak_randomness_demo do
    # Weak randomness - predictable random numbers
    :rand.seed(:exrop, {1, 2, 3})  # Fixed seed
    weak_token = :rand.uniform(1000000)
    IO.puts("Predictable session token: #{weak_token}")
    
    # Using current time as seed (predictable)
    time_seed = System.system_time(:nanosecond)
    :rand.seed(:exrop, {time_seed, 0, 0})
    time_based_token = :rand.uniform(1000000)
    IO.puts("Time-based token: #{time_based_token}")
  end

  def information_disclosure_demo do
    try do
      # Simulating a database connection error
      raise "Database connection failed: host=localhost, user=admin, password=#{@database_password}"
    rescue
      e ->
        # Information disclosure through error messages
        IO.puts("Full error with sensitive info: #{Exception.message(e)}")
        IO.puts("Stack trace: #{Exception.format_stacktrace(__STACKTRACE__)}")
        IO.puts("API Token for debugging: #{@api_token}")
    end
  end

  def sql_injection_simulation do
    IO.write("Enter user ID: ")
    user_id = IO.read(:stdio, :line) |> String.trim()
    
    # SQL injection vulnerability (simulated)
    # In a real app, this would be passed to a database query
    query = "SELECT * FROM users WHERE id = #{user_id}"
    IO.puts("Executing vulnerable query: #{query}")
    
    # Command injection through system calls
    IO.write("Enter filename to process: ")
    filename = IO.read(:stdio, :line) |> String.trim()
    
    # Command injection vulnerability
    command = "ls -la #{filename}"
    IO.puts("Executing command: #{command}")
    
    try do
      {output, exit_code} = System.cmd("sh", ["-c", command])
      IO.puts("Command output: #{output}")
      IO.puts("Exit code: #{exit_code}")
    rescue
      e -> IO.puts("Command execution error: #{inspect(e)}")
    end
  end

  def unsafe_process_operations do
    IO.write("Enter process name to start: ")
    process_name = IO.read(:stdio, :line) |> String.trim()
    
    # Unsafe process spawning with user input
    pid = spawn(fn ->
      # This could be dangerous if process_name contains malicious code
      apply(String.to_atom(process_name), :start, [])
    end)
    
    IO.puts("Started process: #{inspect(pid)}")
  rescue
    e -> IO.puts("Process spawn error: #{inspect(e)}")
  end

  def regex_dos_demo do
    IO.write("Enter text to match against complex regex: ")
    user_text = IO.read(:stdio, :line) |> String.trim()
    
    # ReDoS vulnerability - catastrophic backtracking
    vulnerable_regex = ~r/^(a+)+b$/
    
    start_time = System.monotonic_time(:millisecond)
    result = Regex.match?(vulnerable_regex, user_text)
    end_time = System.monotonic_time(:millisecond)
    
    IO.puts("Regex match result: #{result}")
    IO.puts("Time taken: #{end_time - start_time} ms")
  end

  # GenServer with state injection vulnerability
  defmodule VulnerableServer do
    use GenServer

    def start_link(_) do
      GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
    end

    def init(state) do
      {:ok, state}
    end

    # Vulnerable: allows arbitrary state injection
    def handle_call({:update_state, new_state}, _from, _state) do
      {:reply, :ok, new_state}
    end

    def handle_call(:get_state, _from, state) do
      {:reply, state, state}
    end
  end
end

# Start the application
VulnerableApp.main()
