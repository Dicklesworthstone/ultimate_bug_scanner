using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using Microsoft.AspNetCore.Http;

public static class DapperSqlClean
{
    public static IEnumerable<int> Query(IDbConnection connection, HttpRequest request)
    {
        return connection.Query<int>("SELECT Id FROM Users WHERE Id = @id",
            new { id = request.Query["id"].ToString() });
    }

    public static Task<int> Update(IDbConnection connection, HttpRequest request)
    {
        return connection.ExecuteAsync(param: new { name = request.Form["name"].ToString() },
            sql: "UPDATE Users SET Name = @name WHERE Id = 1");
    }

    public static int ThroughHelper(IDbConnection connection, HttpRequest request)
    {
        return Execute(connection, request.Headers["X-Name"].ToString());
    }

    private static int Execute(IDbConnection connection, string name)
    {
        return SqlMapper.Execute(cnn: connection, param: new { name },
            sql: "DELETE FROM Users WHERE Name = @name");
    }
}
