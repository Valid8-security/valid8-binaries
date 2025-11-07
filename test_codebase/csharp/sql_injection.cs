using System.Data.SqlClient;

public class DatabaseHelper
{
    public SqlDataReader GetUser(string username)
    {
        var conn = new SqlConnection("Server=localhost;Database=test;User Id=user;Password=pass;");
        // CWE-89: SQL Injection
        string query = $"SELECT * FROM users WHERE username = '{username}'";
        var cmd = new SqlCommand(query, conn);
        return cmd.ExecuteReader();
    }
}