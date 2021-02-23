defmodule Rumbl.Auth do
  import Plug.Conn
  import Bcrypt, only: [check_pass: 2, no_user_verify: 0]

  def init(opts) do
    Keyword.fetch!(opts, :repo)
  end

  def call(conn, repo) do
    user_id = get_session(conn, :user_id)
    user = user_id && repo.get(Rumbl.User, user_id)
    assign(conn, :current_user, user)
  end

  def login(conn, user) do
    conn
    |> assign(:current_user, user)
    |> put_session(:user_id, user.id)
    |> configure_session(renew: true)
  end

  def logout(conn) do
    configure_session(conn, drop: true)
  end

  def login_by_username_and_pass(conn, username, given_pass, opts) do
    repo = Keyword.fetch!(opts, :repo)
    user = repo.get_by(Rumbl.User, username: username)

    case check_pass(user, given_pass) do
      {:error, "invalid password"} ->
        {:error, :unauthorized, conn}

      {:error, "invalid user-identifier"} ->
        {:error, :not_found, conn}

      {:ok, user} ->
        {:ok, login(conn, user)}

      _ ->
        {:error, :other, conn}
    end
  end
end
