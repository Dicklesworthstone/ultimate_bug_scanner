using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using Microsoft.AspNetCore.Http;

public static class DapperSqlBuggy
{
    public static IEnumerable<int> Query(IDbConnection connection, HttpRequest request)
    {
        var sql = request.Query["sql"].ToString();
        return connection.Query<int>(sql, new { id = request.Query["id"].ToString() });
    }

    public static Task<int> Update(IDbConnection connection, HttpRequest request)
    {
        var sql = request.Form["sql"].ToString();
        return connection.ExecuteAsync(sql: sql, param: new { id = request.Query["id"].ToString() });
    }

    public static int ThroughHelper(IDbConnection connection, HttpRequest request)
    {
        return Execute(connection, request.Headers["X-Sql"].ToString());
    }

    private static int Execute(IDbConnection connection, string text)
    {
        return SqlMapper.Execute(connection, text);
    }
}
