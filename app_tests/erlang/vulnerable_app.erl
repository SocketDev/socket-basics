-module(vulnerable_app).
-export([main/0, start/0]).

% Hardcoded secrets
-define(SECRET_KEY, "erlang_super_secret_2023").
-define(API_TOKEN, "erl_1234567890abcdef").
-define(DB_PASSWORD, "admin123!@#").

main() ->
    io:format("=== Vulnerable Erlang Application ===~n"),
    io:format("Secret Key: ~s~n", [?SECRET_KEY]),
    
    io:format("~n1. Testing atom exhaustion vulnerability...~n"),
    atom_exhaustion_demo(),
    
    io:format("~n2. Testing code injection...~n"),
    code_injection_demo(),
    
    io:format("~n3. Testing unsafe deserialization...~n"),
    unsafe_deserialization_demo(),
    
    io:format("~n4. Testing command injection...~n"),
    command_injection_demo(),
    
    io:format("~n5. Testing weak randomness...~n"),
    weak_randomness_demo(),
    
    io:format("~n6. Testing information disclosure...~n"),
    information_disclosure_demo(),
    
    ok.

start() ->
    main().

atom_exhaustion_demo() ->
    io:format("Enter dynamic atom name: "),
    {ok, [UserInput]} = io:fread("", "~s"),
    
    try
        % Atom exhaustion vulnerability - converts user input directly to atom
        % This can exhaust the atom table and crash the VM
        DangerousAtom = list_to_atom(UserInput),
        io:format("Created atom: ~w~n", [DangerousAtom])
    catch
        Error:Reason ->
            io:format("Atom creation error: ~w:~w~n", [Error, Reason])
    end.

code_injection_demo() ->
    io:format("Enter Erlang expression to evaluate: "),
    {ok, [UserCode]} = io:fread("", "~s"),
    
    try
        % Code injection vulnerability - evaluates user input as Erlang code
        {ok, Tokens, _} = erl_scan:string(UserCode ++ "."),
        {ok, ParsedExpr} = erl_parse:parse_exprs(Tokens),
        {value, Result, _} = erl_eval:exprs(ParsedExpr, []),
        io:format("Code result: ~w~n", [Result])
    catch
        Error:Reason ->
            io:format("Code evaluation error: ~w:~w~n", [Error, Reason])
    end.

unsafe_deserialization_demo() ->
    io:format("Enter base64 encoded term to deserialize: "),
    {ok, [UserInput]} = io:fread("", "~s"),
    
    try
        % Unsafe deserialization - directly deserializes user input
        % This can lead to code execution if malicious terms are provided
        DecodedBinary = base64:decode(UserInput),
        Term = binary_to_term(DecodedBinary),
        io:format("Deserialized term: ~w~n", [Term])
    catch
        Error:Reason ->
            io:format("Deserialization error: ~w:~w~n", [Error, Reason])
    end.

command_injection_demo() ->
    io:format("Enter filename to list: "),
    {ok, [FileName]} = io:fread("", "~s"),
    
    % Command injection vulnerability
    Command = "ls -la " ++ FileName,
    io:format("Executing command: ~s~n", [Command]),
    
    try
        Result = os:cmd(Command),
        io:format("Command output: ~s~n", [Result])
    catch
        Error:Reason ->
            io:format("Command execution error: ~w:~w~n", [Error, Reason])
    end.

weak_randomness_demo() ->
    % Weak randomness - predictable random numbers
    random:seed(1, 2, 3),  % Fixed seed (deprecated but still vulnerable)
    WeakToken = random:uniform(1000000),
    io:format("Predictable session token: ~w~n", [WeakToken]),
    
    % Using current time as seed (predictable)
    {A, B, C} = now(),
    random:seed(A, B, C),
    TimeBasedToken = random:uniform(1000000),
    io:format("Time-based token: ~w~n", [TimeBasedToken]).

information_disclosure_demo() ->
    try
        % Simulating a database connection error
        error({database_connection_failed, 
               [{host, "localhost"}, 
                {user, "admin"}, 
                {password, ?DB_PASSWORD}]})
    catch
        Error:Reason ->
            % Information disclosure through error messages
            io:format("Full error with sensitive info: ~w:~w~n", [Error, Reason]),
            io:format("Stack trace: ~p~n", [erlang:get_stacktrace()]),
            io:format("API Token for debugging: ~s~n", [?API_TOKEN])
    end.

% Vulnerable process with state injection
vulnerable_server() ->
    receive
        {update_state, NewState} ->
            % Vulnerable: allows arbitrary state injection
            io:format("State updated to: ~w~n", [NewState]),
            vulnerable_server_loop(NewState);
        {get_state, From} ->
            From ! {state, undefined},
            vulnerable_server()
    end.

vulnerable_server_loop(State) ->
    receive
        {update_state, NewState} ->
            io:format("State updated from ~w to ~w~n", [State, NewState]),
            vulnerable_server_loop(NewState);
        {get_state, From} ->
            From ! {state, State},
            vulnerable_server_loop(State);
        {execute, Code} ->
            % Dangerous: executes arbitrary code
            try
                {ok, Tokens, _} = erl_scan:string(Code ++ "."),
                {ok, ParsedExpr} = erl_parse:parse_exprs(Tokens),
                {value, Result, _} = erl_eval:exprs(ParsedExpr, []),
                io:format("Executed code result: ~w~n", [Result])
            catch
                Error:Reason ->
                    io:format("Code execution error: ~w:~w~n", [Error, Reason])
            end,
            vulnerable_server_loop(State)
    end.

% SQL injection simulation (would be used with a database driver)
sql_injection_simulation() ->
    io:format("Enter user ID: "),
    {ok, [UserId]} = io:fread("", "~s"),
    
    % SQL injection vulnerability (simulated)
    Query = "SELECT * FROM users WHERE id = " ++ UserId,
    io:format("Executing vulnerable query: ~s~n", [Query]),
    
    % In a real application, this would be passed to a database
    ok.

% Buffer overflow simulation using binary operations
buffer_overflow_simulation() ->
    io:format("Enter data to process: "),
    {ok, [UserData]} = io:fread("", "~s"),
    
    % Simulated buffer overflow - processing user data without bounds checking
    SmallBuffer = binary:part(list_to_binary(UserData), 0, min(length(UserData), 64)),
    LargeData = list_to_binary(UserData),
    
    io:format("Small buffer size: ~w~n", [byte_size(SmallBuffer)]),
    io:format("Large data size: ~w~n", [byte_size(LargeData)]),
    
    % Potential issue: assuming buffer is always smaller
    if 
        byte_size(LargeData) > 64 ->
            io:format("WARNING: Data larger than buffer, potential overflow!~n");
        true ->
            io:format("Data fits in buffer~n")
    end.

% Race condition vulnerability
race_condition_demo() ->
    SharedState = spawn(fun() -> shared_state_process(0) end),
    
    % Spawn multiple processes that modify shared state without synchronization
    spawn(fun() -> 
        timer:sleep(100),
        SharedState ! {increment, self()},
        receive Msg -> io:format("Process 1 got: ~w~n", [Msg]) end
    end),
    
    spawn(fun() -> 
        timer:sleep(100),
        SharedState ! {increment, self()},
        receive Msg -> io:format("Process 2 got: ~w~n", [Msg]) end
    end),
    
    timer:sleep(500).

shared_state_process(State) ->
    receive
        {increment, From} ->
            % Race condition: read-modify-write without proper synchronization
            NewState = State + 1,
            timer:sleep(10),  % Simulate some processing time
            From ! {state, NewState},
            shared_state_process(NewState);
        {get_state, From} ->
            From ! {state, State},
            shared_state_process(State)
    end.
