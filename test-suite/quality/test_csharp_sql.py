"""Independent Dapper SQL oracle, frozen before the new analyzer was inspected.

The labels describe the selected in-file model: real Dapper string-SQL calls,
resolved ADO.NET receivers and ASP.NET request inputs.  A clean label means no
proven request-to-SQL flow in that model, not a claim about arbitrary callers.
Selected CommandDefinition values retain the query captured at construction;
deferred execution and unresolved dispatch remain explicit boundaries.
Sources are parsed with the actual C# grammar when available;
this suite does not pretend that parsing compiles or executes Dapper.

Runtime sources and complete CLI captures stay in test-suite/artifacts.  Set
UBS_CSHARP_SQL_PUBLIC=1 to enable the actual module/meta acceptance group.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "modules/helpers"))
RULE = "cs.security.sql-injection"
ARTIFACTS = ROOT / "test-suite/artifacts/dapper-independent"
HEADER = """using System;
using System.Data;
using System.Data.Common;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Dapper;
"""


def source(body: str, *, parameters: str = "IDbConnection db, HttpRequest http, bool flag",
           helpers: str = "", async_: bool = False, extra: str = "") -> str:
    """Produce complete C# declarations; expected positions come from markers."""
    signature = "async Task" if async_ else "void"
    body = textwrap.indent(textwrap.dedent(body).strip(), "        ")
    helpers = textwrap.indent(textwrap.dedent(helpers).strip(), "    ") if helpers else ""
    return (HEADER + extra + "\nclass Row { public int Id { get; set; } }\nclass C {\n"
            + (helpers + "\n" if helpers else "")
            + f"    {signature} Run({parameters}) {{\n{body}\n    }}\n}}\n")


@dataclass(frozen=True)
class Case:
    name: str
    code: str
    partial: bool = False

    @property
    def expected(self) -> list[tuple[str, int, int]]:
        result = []
        for line, text in enumerate(self.code.splitlines(), 1):
            if "// @sql " not in text:
                continue
            call = text.split("// @sql ", 1)[1].strip()
            statement = text.split("// @sql ", 1)[0]
            assert statement.count(call) == 1, (self.name, line, call)
            result.append((RULE, line, statement.index(call) + 1))
        return result


# These 40 complete cases were labeled from source/API semantics before the
# proposed Dapper analyzer was read or executed.  Keep their labels independent.
CASES = (
    Case("sync_string_sql_families", source('''
        var sql = http.Query["sql"].ToString();
        db.Execute(sql); // @sql db.Execute
        db.ExecuteScalar(sql); // @sql db.ExecuteScalar
        db.ExecuteScalar<int>(sql); // @sql db.ExecuteScalar
        db.Query(sql); // @sql db.Query
        db.Query<int>(sql); // @sql db.Query
        db.QueryFirst(sql); // @sql db.QueryFirst
        db.QueryFirst<int>(sql); // @sql db.QueryFirst
        db.QueryFirstOrDefault(sql); // @sql db.QueryFirstOrDefault
        db.QueryFirstOrDefault<int>(sql); // @sql db.QueryFirstOrDefault
        db.QuerySingle(sql); // @sql db.QuerySingle
        db.QuerySingle<int>(sql); // @sql db.QuerySingle
        db.QuerySingleOrDefault(sql); // @sql db.QuerySingleOrDefault
        db.QuerySingleOrDefault<int>(sql); // @sql db.QuerySingleOrDefault
    ''')),
    Case("async_string_sql_families", source('''
        var sql = http.Query["sql"].ToString();
        await db.ExecuteAsync(sql); // @sql db.ExecuteAsync
        await db.ExecuteScalarAsync(sql); // @sql db.ExecuteScalarAsync
        await db.ExecuteScalarAsync<int>(sql); // @sql db.ExecuteScalarAsync
        await db.QueryAsync(sql); // @sql db.QueryAsync
        await db.QueryAsync<int>(sql); // @sql db.QueryAsync
        await db.QueryFirstAsync(sql); // @sql db.QueryFirstAsync
        await db.QueryFirstAsync<int>(sql); // @sql db.QueryFirstAsync
        await db.QueryFirstOrDefaultAsync(sql); // @sql db.QueryFirstOrDefaultAsync
        await db.QueryFirstOrDefaultAsync<int>(sql); // @sql db.QueryFirstOrDefaultAsync
        await db.QuerySingleAsync(sql); // @sql db.QuerySingleAsync
        await db.QuerySingleAsync<int>(sql); // @sql db.QuerySingleAsync
        await db.QuerySingleOrDefaultAsync(sql); // @sql db.QuerySingleOrDefaultAsync
        await db.QuerySingleOrDefaultAsync<int>(sql); // @sql db.QuerySingleOrDefaultAsync
    ''', async_=True)),
    Case("type_leading_sync_sql_position", source('''
        var sql = http.Query["sql"].ToString();
        db.Query(typeof(Row), sql); // @sql db.Query
        db.QueryFirst(typeof(Row), sql); // @sql db.QueryFirst
        db.QueryFirstOrDefault(typeof(Row), sql); // @sql db.QueryFirstOrDefault
        db.QuerySingle(typeof(Row), sql); // @sql db.QuerySingle
        db.QuerySingleOrDefault(typeof(Row), sql); // @sql db.QuerySingleOrDefault
    ''')),
    Case("type_leading_async_sql_position", source('''
        var sql = http.Query["sql"].ToString();
        await db.QueryAsync(typeof(Row), sql); // @sql db.QueryAsync
        await db.QueryFirstAsync(typeof(Row), sql); // @sql db.QueryFirstAsync
        await db.QueryFirstOrDefaultAsync(typeof(Row), sql); // @sql db.QueryFirstOrDefaultAsync
        await db.QuerySingleAsync(typeof(Row), sql); // @sql db.QuerySingleAsync
        await db.QuerySingleOrDefaultAsync(typeof(Row), sql); // @sql db.QuerySingleOrDefaultAsync
    ''', async_=True)),
    Case("static_type_leading_and_named_cnn", source('''
        var sql = http.Query["sql"].ToString();
        await SqlMapper.QueryAsync(db, typeof(Row), sql); // @sql SqlMapper.QueryAsync
        await SqlMapper.QueryAsync(type: typeof(Row), sql: sql, cnn: db, param: new { id = 1 }); // @sql SqlMapper.QueryAsync
        SqlMapper.Execute(cnn: db, sql: sql); // @sql SqlMapper.Execute
    ''', async_=True)),
    Case("named_sql_is_not_the_param_argument", source('''
        db.Execute(param: new { id = 1 }, sql: http.Query["sql"].ToString()); // @sql db.Execute
    ''')),
    Case("interpolation_remains_unsafe_with_parameters", source('''
        var id = http.Query["id"].ToString();
        db.Query<int>($"select Id from Users where Name = '{id}'", new { id }); // @sql db.Query
    ''')),
    Case("concatenated_sql_execution_location", source('''
        var name = http.Query["name"].ToString();
        var sql = "SELECT Id FROM Users WHERE Name = '" + name + "'";
        db.Query<int>(sql); // @sql db.Query
    ''')),
    Case("bound_values_are_not_sql_text", source('''
        var value = http.Query["id"].ToString();
        db.Execute("delete from Users where Id = @id", new { id = value });
        db.Query<int>("select Id from Users where Name = @name", new { name = value });
        db.QueryFirst<int>(sql: "select Id from Users where Id = @id", param: new { id = value });
        db.ExecuteScalar<int>("select count(*) from Users where Id = @id", new { id = value });
    ''')),
    Case("type_leading_bound_values_are_clean", source('''
        var value = http.Query["id"].ToString();
        db.Query(typeof(Row), "select Id from Users where Id = @id", new { id = value });
        await db.QueryAsync(typeof(Row), "select Id from Users where Id = @id", new { id = value });
        await SqlMapper.QueryAsync(cnn: db, type: typeof(Row), param: new { id = value }, sql: "select Id from Users where Id = @id");
    ''', async_=True)),
    Case("literal_interpolation_is_clean", source('''
        var table = "Users";
        db.Query<int>($"select Id from {table}");
    ''')),
    Case("comment_and_string_decoys_are_clean", source('''
        // db.Execute(http.Query["sql"].ToString());
        var documentation = @"db.Query(http.Query[""sql""]);";
        db.Execute("select 1");
    ''')),
    Case("request_connection_and_query_aliases", source('''
        var input = http;
        var connection = db;
        var query = input.Query["sql"].ToString();
        connection.Execute(query); // @sql connection.Execute
    ''')),
    Case("literal_rebinding_kills_query_taint", source('''
        var sql = http.Query["sql"].ToString();
        sql = "select 1";
        db.Execute(sql);
    ''')),
    Case("one_clean_branch_does_not_erase_taint", source('''
        var sql = http.Query["sql"].ToString();
        if (flag) { sql = "select 1"; }
        db.Execute(sql); // @sql db.Execute
    ''')),
    Case("both_clean_branches_kill_taint", source('''
        var sql = http.Query["sql"].ToString();
        if (flag) { sql = "select 1"; } else { sql = "select 2"; }
        db.Execute(sql);
    ''')),
    Case("source_on_one_branch_reaches_sink", source('''
        var sql = "select 1";
        if (flag) { sql = http.Query["sql"].ToString(); }
        db.Execute(sql); // @sql db.Execute
    ''')),
    Case("local_helper_return_preserves_taint", source('''
        var sql = Identity(http.Query["sql"].ToString());
        db.Execute(sql); // @sql db.Execute
    ''', helpers='''
        string Identity(string value) { return value; }
    ''')),
    Case("local_helper_constant_return_is_clean", source('''
        db.Execute(Fixed(http.Query["sql"].ToString()));
    ''', helpers='''
        string Fixed(string value) { return "select 1"; }
    ''')),
    Case("local_helper_sink_reports_execution", source('''
        ExecuteQuery(db, http.Query["sql"].ToString());
    ''', helpers='''
        void ExecuteQuery(IDbConnection connection, string text) {
            connection.Execute(text); // @sql connection.Execute
        }
    ''')),
    Case("local_helper_named_arguments", source('''
        ExecuteQuery(text: http.Query["sql"].ToString(), connection: db);
    ''', helpers='''
        void ExecuteQuery(IDbConnection connection, string text) {
            connection.Execute(text); // @sql connection.Execute
        }
    ''')),
    Case("local_helper_returns_connection_identity", source('''
        var connection = Identity(db);
        connection.Query<int>(http.Query["sql"].ToString()); // @sql connection.Query
    ''', helpers='''
        IDbConnection Identity(IDbConnection connection) { return connection; }
    ''')),
    Case("http_context_request_is_real_source", source('''
        db.Execute(context.Request.Query["sql"].ToString()); // @sql db.Execute
    ''', parameters="IDbConnection db, HttpContext context")),
    Case("controllerbase_implicit_request", HEADER + '''
class C : Microsoft.AspNetCore.Mvc.ControllerBase {
    void Run(IDbConnection db) {
        db.Execute(Request.Query["sql"].ToString()); // @sql db.Execute
    }
}
'''),
    Case("form_header_and_cookie_sources", source('''
        db.Execute(http.Form["sql"].ToString()); // @sql db.Execute
        db.Execute(http.Headers["X-Sql"].ToString()); // @sql db.Execute
        db.Execute(http.Cookies["sql"]); // @sql db.Execute
    ''')),
    Case("real_sqlconnection_type_identities", source('''
        oldConnection.Execute(http.Query["sql"].ToString()); // @sql oldConnection.Execute
        newConnection.Execute(http.Query["sql"].ToString()); // @sql newConnection.Execute
    ''', parameters="System.Data.SqlClient.SqlConnection oldConnection, Microsoft.Data.SqlClient.SqlConnection newConnection, HttpRequest http")),
    Case("real_dbconnection_type_identity", source('''
        db.Query<int>(http.Query["sql"].ToString()); // @sql db.Query
    ''', parameters="DbConnection db, HttpRequest http")),
    Case("using_aliases_resolve_real_types", '''using Db = System.Data.IDbConnection;
using Web = Microsoft.AspNetCore.Http.HttpRequest;
using Sql = Dapper.SqlMapper;
class C {
    void Run(Db db, Web http) {
        Sql.Execute(db, http.Query["sql"].ToString()); // @sql Sql.Execute
    }
}
'''),
    Case("request_variable_name_is_not_provenance", HEADER + '''
class RequestData { public string Query = "select 1"; }
class C {
    void Run(IDbConnection db, RequestData request) {
        db.Execute(request.Query);
    }
}
'''),
    Case("local_httprequest_class_shadows_import", HEADER + '''
class HttpRequest { public string Query = "select 1"; }
class C {
    void Run(IDbConnection db, HttpRequest http) {
        db.Execute(http.Query);
    }
}
'''),
    Case("same_named_method_on_local_object_is_clean", HEADER + '''
class LocalDb { public void Query(string sql) { } }
class C {
    void Run(LocalDb db, HttpRequest http) {
        db.Query(http.Query["sql"].ToString());
    }
}
'''),
    Case("local_sqlmapper_class_shadows_import", HEADER + '''
class SqlMapper { public static void Execute(IDbConnection cnn, string sql) { } }
class C {
    void Run(IDbConnection db, HttpRequest http) {
        SqlMapper.Execute(db, http.Query["sql"].ToString());
    }
}
'''),
    Case("relative_dapper_namespace_is_not_global_dapper", HEADER + '''
namespace App.Dapper {
    public static class SqlMapper {
        public static void Execute(IDbConnection cnn, string sql) { }
    }
}
namespace App {
    class C {
        void Run(IDbConnection db, HttpRequest http) {
            Dapper.SqlMapper.Execute(db, http.Query["sql"].ToString());
        }
    }
}
'''),
    Case("global_dapper_survives_local_sqlmapper_shadow", HEADER + '''
class SqlMapper { public static void Execute(IDbConnection cnn, string sql) { } }
class C {
    void Run(IDbConnection db, HttpRequest http) {
        global::Dapper.SqlMapper.Execute(db, http.Query["sql"].ToString()); // @sql global::Dapper.SqlMapper.Execute
    }
}
'''),
    Case("local_function_query_is_not_dapper", source('''
        void Query(string sql) { }
        Query(http.Query["sql"].ToString());
    ''')),
    Case("local_request_shadows_controller_property", HEADER + '''
class LocalInput { public string Query = "select 1"; }
class C : Microsoft.AspNetCore.Mvc.ControllerBase {
    void Run(IDbConnection db) {
        var Request = new LocalInput();
        db.Execute(Request.Query);
    }
}
'''),
    Case("arbitrary_string_parameter_is_not_request_source", source('''
        db.Execute(sql);
    ''', parameters="IDbConnection db, string sql")),
    Case("unrelated_method_names_do_not_share_taint", source('''
        ExecuteQuery(db, "select 1");
    ''', helpers='''
        void ReadInput(HttpRequest http) { var sql = http.Query["sql"].ToString(); }
        void ExecuteQuery(IDbConnection db, string sql) { db.Execute(sql); }
    ''')),
    Case("clean_and_unsafe_callers_share_one_execution_location", source('''
        ExecuteQuery(db, "select 1");
        ExecuteQuery(db, http.Query["sql"].ToString());
    ''', helpers='''
        void ExecuteQuery(IDbConnection connection, string text) {
            connection.Execute(text); // @sql connection.Execute
        }
    ''')),
    Case("string_format_does_not_parameterize_sql", source('''
        var sql = string.Format("select Id from Users where Name = '{0}'", http.Query["name"].ToString());
        db.Query<int>(sql); // @sql db.Query
    ''')),
)

BOUNDARIES = (
    Case("deferred_query_is_explicitly_partial", source('''
        db.Query<int>(http.Query["sql"].ToString(), buffered: false);
    '''), partial=True),
    Case("unknown_buffered_policy_is_explicitly_partial", source('''
        db.Query<int>(http.Query["sql"].ToString(), buffered: flag);
    '''), partial=True),
    Case("multimapping_is_explicitly_partial", source('''
        db.Query<int, int, int>(http.Query["sql"].ToString(), (a, b) => a + b);
    '''), partial=True),
    Case("dynamic_receiver_is_explicitly_partial", source('''
        db.Query(http.Query["sql"].ToString());
    ''', parameters="dynamic db, HttpRequest http"), partial=True),
    Case("known_finding_precedes_unsupported_command", source('''
        db.Execute(http.Query["sql"].ToString()); // @sql db.Execute
        var command = new CommandDefinition(http.Query["sql"].ToString(), flags: CommandFlags.None);
        db.Query<int>(command);
    '''), partial=True),
)


# Independently specified before the CommandDefinition implementation.  Dapper's
# readonly struct copies CommandText at construction; Parameters is a separate
# operand.  Query<T> can defer execution, unlike Execute/Scalar/First/Single.
# These are actual overloads, not all syntactically plausible combinations:
# sync Query has no non-generic or Type-leading CommandDefinition overload.
# API sources inspected 2026-11-08:
# https://github.com/DapperLib/Dapper/blob/main/Dapper/CommandDefinition.cs
# https://github.com/DapperLib/Dapper/blob/main/Dapper/CommandFlags.cs
# https://github.com/DapperLib/Dapper/blob/main/Dapper/SqlMapper.cs
# https://github.com/DapperLib/Dapper/blob/main/Dapper/SqlMapper.Async.cs
COMMAND_CASES = (
    Case("command_sync_eager_families", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        db.Execute(command); // @sql db.Execute
        db.ExecuteScalar(command); // @sql db.ExecuteScalar
        db.ExecuteScalar<int>(command); // @sql db.ExecuteScalar
        db.Query<int>(command); // @sql db.Query
        db.QueryFirst<int>(command); // @sql db.QueryFirst
        db.QueryFirstOrDefault<int>(command); // @sql db.QueryFirstOrDefault
        db.QuerySingle<int>(command); // @sql db.QuerySingle
        db.QuerySingleOrDefault<int>(command); // @sql db.QuerySingleOrDefault
    ''')),
    Case("command_async_eager_families", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        await db.ExecuteAsync(command); // @sql db.ExecuteAsync
        await db.ExecuteScalarAsync(command); // @sql db.ExecuteScalarAsync
        await db.ExecuteScalarAsync<int>(command); // @sql db.ExecuteScalarAsync
        await db.QueryAsync(command); // @sql db.QueryAsync
        await db.QueryAsync<int>(command); // @sql db.QueryAsync
        await db.QueryFirstAsync(command); // @sql db.QueryFirstAsync
        await db.QueryFirstAsync<int>(command); // @sql db.QueryFirstAsync
        await db.QueryFirstOrDefaultAsync(command); // @sql db.QueryFirstOrDefaultAsync
        await db.QueryFirstOrDefaultAsync<int>(command); // @sql db.QueryFirstOrDefaultAsync
        await db.QuerySingleAsync(command); // @sql db.QuerySingleAsync
        await db.QuerySingleAsync<int>(command); // @sql db.QuerySingleAsync
        await db.QuerySingleOrDefaultAsync(command); // @sql db.QuerySingleOrDefaultAsync
        await db.QuerySingleOrDefaultAsync<int>(command); // @sql db.QuerySingleOrDefaultAsync
    ''', async_=True)),
    Case("command_async_type_leading_arguments", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        await db.QueryAsync(typeof(Row), command); // @sql db.QueryAsync
        await db.QueryFirstAsync(typeof(Row), command); // @sql db.QueryFirstAsync
        await db.QueryFirstOrDefaultAsync(typeof(Row), command); // @sql db.QueryFirstOrDefaultAsync
        await db.QuerySingleAsync(typeof(Row), command); // @sql db.QuerySingleAsync
        await db.QuerySingleOrDefaultAsync(typeof(Row), command); // @sql db.QuerySingleOrDefaultAsync
    ''', async_=True)),
    Case("command_inline_constructor_is_consumed", source('''
        db.Execute(new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text)); // @sql db.Execute
    ''')),
    Case("command_default_policy_uses_sql_text", source('''
        var sql = "select Id from Users where Name = '" + http.Query["name"].ToString() + "'";
        var command = new CommandDefinition(sql);
        db.Query<int>(command); // @sql db.Query
    ''')),
    Case("command_named_constructor_and_sink_arguments", source('''
        var command = new CommandDefinition(parameters: new { id = 1 }, commandType: CommandType.Text,
            commandText: http.Query["sql"].ToString());
        SqlMapper.Execute(command: command, cnn: db); // @sql SqlMapper.Execute
    ''')),
    Case("command_positional_constructor_roles", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), new { id = 1 },
            null, 30, CommandType.Text, CommandFlags.Buffered);
        db.Execute(command: command); // @sql db.Execute
    ''')),
    Case("command_parameter_data_does_not_become_sql", source('''
        var command = new CommandDefinition("select Id from Users where Name = @name",
            new { name = http.Query["name"].ToString() });
        db.Query<int>(command);
        db.ExecuteScalar<int>(command);
    ''')),
    Case("command_named_parameters_do_not_become_sql", source('''
        var command = new CommandDefinition(parameters: new { sql = http.Query["sql"].ToString() },
            flags: CommandFlags.Buffered, commandText: "select @sql", commandType: CommandType.Text);
        db.Execute(command: command);
    ''')),
    Case("command_parameters_do_not_sanitize_interpolation", source('''
        var command = new CommandDefinition($"select Id from Users where Name = '{http.Query["name"]}' and Id = @id",
            new { id = 1 });
        db.Query<int>(command); // @sql db.Query
    ''')),
    Case("command_query_text_is_captured_before_reassignment", source('''
        var sql = http.Query["sql"].ToString();
        var command = new CommandDefinition(sql, commandType: CommandType.Text);
        sql = "select 1";
        db.Execute(command); // @sql db.Execute
    ''')),
    Case("command_safe_query_capture_survives_tainted_reassignment", source('''
        var sql = "select @name";
        var command = new CommandDefinition(sql, new { name = http.Query["name"].ToString() });
        sql = http.Query["sql"].ToString();
        db.Execute(command);
    ''')),
    Case("command_value_copy_retains_original_query", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        var copied = command;
        command = new CommandDefinition("select 1");
        db.Execute(copied); // @sql db.Execute
        db.Execute(command);
    ''')),
    Case("command_safe_value_copy_is_independent", source('''
        var command = new CommandDefinition("select @name", new { name = http.Query["name"].ToString() });
        var copied = command;
        command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        db.Execute(copied);
        db.Execute(command); // @sql db.Execute
    ''')),
    Case("command_branch_join_retains_unsafe_query", source('''
        var command = new CommandDefinition("select 1");
        if (flag) {
            command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        }
        db.Execute(command); // @sql db.Execute
    ''')),
    Case("command_branch_join_bound_data_stays_clean", source('''
        var command = new CommandDefinition("select 1");
        if (flag) {
            command = new CommandDefinition("select @sql", new { sql = http.Query["sql"].ToString() });
        }
        db.Execute(command);
    ''')),
    Case("command_local_factory_returns_captured_query", source('''
        var command = Make(http.Query["sql"].ToString());
        db.Execute(command); // @sql db.Execute
    ''', helpers='''
        CommandDefinition Make(string text) {
            return new CommandDefinition(text, commandType: CommandType.Text);
        }
    ''')),
    Case("command_factory_preserves_separate_data_argument", source('''
        var command = Make("select @value", http.Query["sql"].ToString());
        db.Execute(command);
    ''', helpers='''
        CommandDefinition Make(string text, string data) {
            return new CommandDefinition(text, new { value = data }, commandType: CommandType.Text);
        }
    ''')),
    Case("command_factory_calls_do_not_share_query_state", source('''
        var unsafeCommand = Make(http.Query["sql"].ToString());
        var safeCommand = Make("select 1");
        db.Execute(safeCommand);
        db.Execute(unsafeCommand); // @sql db.Execute
    ''', helpers='''
        CommandDefinition Make(string text) {
            return new CommandDefinition(text, commandType: CommandType.Text);
        }
    ''')),
    Case("command_ref_helper_replaces_safe_query_with_request", source('''
        var command = new CommandDefinition("select 1");
        Replace(ref command, http.Query["sql"].ToString());
        db.Execute(command); // @sql db.Execute
    ''', helpers='''
        void Replace(ref CommandDefinition value, string text) {
            value = new CommandDefinition(text, commandType: CommandType.Text);
        }
    ''')),
    Case("command_ref_helper_replaces_request_with_safe_query", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        Replace(ref command, "select 1");
        db.Execute(command);
    ''', helpers='''
        void Replace(ref CommandDefinition value, string text) {
            value = new CommandDefinition(text, commandType: CommandType.Text);
        }
    ''')),
    Case("command_value_parameter_replacement_does_not_modify_caller", source('''
        var command = new CommandDefinition("select 1");
        Replace(command, http.Query["sql"].ToString());
        db.Execute(command);
    ''', helpers='''
        void Replace(CommandDefinition value, string text) {
            value = new CommandDefinition(text, commandType: CommandType.Text);
        }
    ''')),
    Case("command_factory_property_roles_survive_substitution", source('''
        var command = Make("select @value", http.Query["sql"].ToString());
        db.Execute(command.CommandText);
        db.Execute((string)command.Parameters); // @sql db.Execute
    ''', helpers='''
        CommandDefinition Make(string text, string data) {
            return new CommandDefinition(text, data, commandType: CommandType.Text);
        }
    ''')),
    Case("command_unbuffered_flags_do_not_defer_eager_methods", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text,
            flags: CommandFlags.None);
        db.Execute(command); // @sql db.Execute
        db.ExecuteScalar<int>(command); // @sql db.ExecuteScalar
        db.QueryFirst<int>(command); // @sql db.QueryFirst
        db.QuerySingleOrDefault<int>(command); // @sql db.QuerySingleOrDefault
    ''')),
    Case("command_buffered_flag_combination_is_eager", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text,
            flags: CommandFlags.Buffered | CommandFlags.NoCache);
        db.Query<int>(command); // @sql db.Query
    ''')),
    Case("command_type_and_namespace_aliases", '''using System.Data;
using Microsoft.AspNetCore.Http;
using QueryCommand = Dapper.CommandDefinition;
using Database = Dapper;
class C {
    void Run(IDbConnection db, HttpRequest http) {
        var command = new QueryCommand(http.Query["sql"].ToString(), commandType: CommandType.Text);
        Database.SqlMapper.Execute(db, command); // @sql Database.SqlMapper.Execute
    }
}
'''),
    Case("command_global_qualified_binding", source('''
        var command = new global::Dapper.CommandDefinition(http.Query["sql"].ToString(),
            commandType: global::System.Data.CommandType.Text);
        global::Dapper.SqlMapper.Execute(db, command); // @sql global::Dapper.SqlMapper.Execute
    ''')),
    Case("command_text_property_preserves_sql_provenance", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        db.Execute(command.CommandText); // @sql db.Execute
    ''')),
    Case("command_text_property_does_not_expose_parameter_data", source('''
        var command = new CommandDefinition("select @value", http.Query["sql"].ToString());
        db.Execute(command.CommandText);
    ''')),
    Case("command_parameter_property_is_data_until_used_as_sql", source('''
        var command = new CommandDefinition("select @value", http.Query["sql"].ToString());
        db.Execute((string)command.Parameters); // @sql db.Execute
    ''')),
    Case("command_unused_construction_is_not_execution", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        Console.WriteLine(command.CommandText);
    ''')),
    Case("command_local_lookalike_is_not_dapper", '''using System.Data;
using Microsoft.AspNetCore.Http;
using Dapper;
class CommandDefinition {
    public CommandDefinition(string text) { }
}
class LocalDatabase {
    public void Execute(CommandDefinition value) { }
}
class C {
    void Run(LocalDatabase db, HttpRequest http) {
        var command = new CommandDefinition(http.Query["sql"].ToString());
        db.Execute(command);
    }
}
'''),
    Case("command_comments_and_strings_are_not_calls", source('''
        // db.Execute(new CommandDefinition(http.Query["sql"].ToString()));
        var example = "new CommandDefinition(request); db.Execute(command)";
        var command = new CommandDefinition("select @example", new { example });
        db.Execute(command);
    ''')),
)

COMMAND_BOUNDARIES = (
    Case("command_target_typed_construction_is_explicitly_partial", source('''
        CommandDefinition command = new(http.Query["sql"].ToString(), commandType: CommandType.Text);
        db.Execute(command);
    '''), partial=True),
    Case("command_local_helper_parameter_requires_projection_summary", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        Send(db, command);
    ''', helpers='''
        void Send(IDbConnection connection, CommandDefinition selected) {
            connection.Execute(selected);
        }
    '''), partial=True),
    Case("command_helper_property_requires_projection_summary", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        Send(db, command);
    ''', helpers='''
        void Send(IDbConnection connection, CommandDefinition selected) {
            connection.Execute(selected.CommandText);
        }
    '''), partial=True),
    Case("command_unbuffered_query_is_explicitly_partial", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text,
            flags: CommandFlags.None);
        db.Query<int>(command);
    '''), partial=True),
    Case("command_unknown_query_flags_are_explicitly_partial", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text,
            flags: selectedFlags);
        db.Query<int>(command);
    ''', parameters="IDbConnection db, HttpRequest http, CommandFlags selectedFlags"), partial=True),
    Case("command_unknown_command_type_is_explicitly_partial", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: selectedType);
        db.Execute(command);
    ''', parameters="IDbConnection db, HttpRequest http, CommandType selectedType"), partial=True),
    Case("command_stored_procedure_is_not_text_sql", source('''
        var command = new CommandDefinition(http.Query["procedure"].ToString(), commandType: CommandType.StoredProcedure);
        db.Execute(command);
    '''), partial=True),
    Case("command_external_value_is_explicitly_partial", source('''
        db.Execute(command);
    ''', parameters="IDbConnection db, CommandDefinition command"), partial=True),
    Case("command_mutable_field_is_not_a_stale_constructor_proof", source('''
        stored = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        db.Execute(stored);
    ''', helpers='''
        CommandDefinition stored = new CommandDefinition("select 1");
    '''), partial=True),
    Case("command_unknown_ref_escape_revokes_captured_value", source('''
        var command = new CommandDefinition("select 1");
        mutator.Replace(ref command);
        db.Execute(command);
    ''', parameters="IDbConnection db, ICommandMutator mutator", extra='''interface ICommandMutator {
    void Replace(ref CommandDefinition command);
}
'''), partial=True),
    Case("command_target_typed_reassignment_revokes_old_value", source('''
        var command = new CommandDefinition("select 1");
        command = new(http.Query["sql"].ToString(), commandType: CommandType.Text);
        db.Execute(command);
    '''), partial=True),
    Case("command_array_mutation_is_not_stale_safe_evidence", source('''
        var commands = new[] { new CommandDefinition("select 1") };
        commands[0] = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        db.Execute(commands[0]);
    '''), partial=True),
    Case("command_array_projection_does_not_union_unselected_query", source('''
        var commands = new[] { new CommandDefinition("select 1"),
            new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text) };
        db.Execute(commands[0]);
    '''), partial=True),
    Case("command_nullable_projection_requires_value_model", source('''
        CommandDefinition? command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        db.Execute(command.Value);
    '''), partial=True),
    Case("command_nullable_projection_does_not_promote_parameter_data", source('''
        CommandDefinition? command = new CommandDefinition("select @value", http.Query["sql"].ToString());
        db.Execute(command.Value);
    '''), partial=True),
    Case("command_default_value_has_no_captured_policy", source('''
        CommandDefinition command = default;
        db.Execute(command);
    '''), partial=True),
    Case("command_argument_assignment_requires_ordered_effects", source('''
        var sql = "select @value";
        var command = new CommandDefinition(parameters: (sql = http.Query["sql"].ToString()),
            commandText: sql, commandType: CommandType.Text);
        db.Execute(command);
    '''), partial=True),
    Case("command_later_argument_write_cannot_rewrite_captured_text", source('''
        var sql = http.Query["sql"].ToString();
        var command = new CommandDefinition(sql, parameters: (sql = "select 1"), commandType: CommandType.Text);
        db.Execute(command);
    '''), partial=True),
    Case("command_shadowed_command_type_is_not_framework_policy", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
        db.Execute(command);
    ''', extra='''static class CommandType {
    public static System.Data.CommandType Text = System.Data.CommandType.StoredProcedure;
}
'''), partial=True),
    Case("command_shadowed_flags_are_not_framework_policy", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text,
            flags: CommandFlags.Buffered);
        db.Query<int>(command);
    ''', extra='''static class CommandFlags {
    public static Dapper.CommandFlags Buffered = Dapper.CommandFlags.None;
}
'''), partial=True),
)


# Two independently reviewed dispatch regressions authorized after the first
# native run.  They do not change the original 40 complete or six boundary
# source/expectation pairs retained in frozen-labels-v1.
REVIEW_CASES = (
    Case("local_extension_body_precedes_imported_dapper", '''using System.Data;
using Microsoft.AspNetCore.Http;
using Dapper;
static class LocalExtensions {
    public static int Execute(this IDbConnection db, string sql) { return 0; }
}
class C {
    void Run(IDbConnection db, HttpRequest http) {
        db.Execute(http.Query["sql"].ToString());
    }
}
'''),
    Case("local_commandtype_text_is_not_framework_text", '''using System.Data;
using Microsoft.AspNetCore.Http;
using Dapper;
static class CommandType {
    public const System.Data.CommandType Text = System.Data.CommandType.StoredProcedure;
}
class C {
    void Run(IDbConnection db, HttpRequest http) {
        db.Execute(http.Query["sql"].ToString(), commandType: CommandType.Text);
    }
}
''', partial=True),
)


def materialize(directory: Path, cases=CASES) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = {}
    for case in cases:
        path = directory / (case.name + ".cs")
        path.write_text(case.code, encoding="utf-8")
        paths[case.name] = path
    return paths


def freeze_receipt(directory: Path) -> dict:
    """Persist independently assigned labels and their exact source bytes."""
    cases = CASES + BOUNDARIES + COMMAND_CASES + COMMAND_BOUNDARIES
    paths = materialize(directory / "cases", cases)
    receipt = {
        "rule": RULE,
        "labels_assigned_before_proposed_analyzer_inspection": True,
        "runtime": sys.version,
        "python_executable": sys.executable,
        "cases": [
            {"name": case.name, "source": str(paths[case.name]),
             "sha256": hashlib.sha256(case.code.encode()).hexdigest(),
             "expected": case.expected, "partial": case.partial}
            for case in cases
        ],
    }
    (directory / "labels.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


@unittest.skipIf(os.environ.get("UBS_CSHARP_SQL_PUBLIC_ONLY") == "1", "native group already run")
class DapperNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = ARTIFACTS / ("native-" + uuid.uuid4().hex[:12])
        cls.paths = materialize(cls.directory, CASES + BOUNDARIES + REVIEW_CASES + COMMAND_CASES + COMMAND_BOUNDARIES)
        cls.analyzer = importlib.import_module("ubs_core.analyzers.taint_csharp_sql")

    def scan_case(self, case: Case):
        findings = []
        error = None
        try:
            findings.extend(self.analyzer.scan_file_findings(self.paths[case.name]))
        except ValueError as exc:
            error = str(exc)
        self.assertEqual(error is not None, case.partial, (case.name, findings, error))
        if case.partial:
            self.assertTrue(error.strip(), (case.name, error))
        actual = sorted((f["rule"], f["line"], f.get("col", 1)) for f in findings)
        self.assertEqual(actual, sorted(case.expected), (case.name, findings, error))
        for finding in findings:
            self.assertEqual(finding["severity"], "critical", finding)
            self.assertEqual(finding.get("category_id"), "csharp.security", finding)
            self.assertEqual(Path(finding["path"]), self.paths[case.name], finding)

    def test_token_budget_is_not_a_clean_report(self):
        case = CASES[0]
        prior = os.environ.get("UBS_CSHARP_SQL_MAX_TOKENS")
        os.environ["UBS_CSHARP_SQL_MAX_TOKENS"] = "16"
        try:
            with self.assertRaisesRegex(ValueError, "(?i)limit|budget|incomplete|tokens"):
                list(self.analyzer.scan_file_findings(self.paths[case.name]))
        finally:
            if prior is None:
                os.environ.pop("UBS_CSHARP_SQL_MAX_TOKENS", None)
            else:
                os.environ["UBS_CSHARP_SQL_MAX_TOKENS"] = prior

    def test_unrelated_existing_security_fixtures_do_not_become_partial(self):
        for family in ("HeaderInjection", "OpenRedirect", "RequestPathTraversal", "Ssrf"):
            for side in ("Buggy", "Clean"):
                path = ROOT / "test-suite/csharp/security" / (family + side + ".cs")
                with self.subTest(fixture=path.name):
                    self.assertEqual(list(self.analyzer.scan_file_findings(path)), [])

    def test_permanent_dapper_buggy_and_clean_fixtures(self):
        for name, expected in (
            ("DapperSqlBuggy.cs", [(RULE, 12, 16), (RULE, 18, 16), (RULE, 28, 16)]),
            ("DapperSqlClean.cs", []),
        ):
            path = ROOT / "test-suite/csharp/security" / name
            with self.subTest(fixture=name):
                findings = list(self.analyzer.scan_file_findings(path))
                self.assertEqual(sorted((row["rule"], row["line"], row["col"]) for row in findings), expected)
                for finding in findings:
                    self.assertEqual((finding["severity"], finding["category_id"]),
                                     ("critical", "csharp.security"), finding)


def _install_native_tests():
    for case in CASES + BOUNDARIES + REVIEW_CASES + COMMAND_CASES + COMMAND_BOUNDARIES:
        def test(self, case=case):
            self.scan_case(case)
        setattr(DapperNativeTests, "test_" + case.name, test)


_install_native_tests()


@unittest.skipUnless(os.environ.get("UBS_CSHARP_SQL_PUBLIC") == "1",
                     "set UBS_CSHARP_SQL_PUBLIC=1 after verified module/helper pins")
class DapperPublicTests(unittest.TestCase):
    """Real scanner commands exercise the independent semantic labels."""

    @classmethod
    def setUpClass(cls):
        cls.directory = ARTIFACTS / ("public-" + uuid.uuid4().hex[:12])
        cls.directory.mkdir(parents=True)
        cls.identity = {
            "python": sys.version,
            "python_executable": sys.executable,
            "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                            text=True).strip(),
            "dotnet": shutil.which("dotnet"),
            "ast_grep": shutil.which("ast-grep"),
            "sources": {
                path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                for path in (
                    "ubs", "modules/ubs-csharp.sh", "modules/helpers/ubs_core/csharp_scan.py",
                    "modules/helpers/ubs_core/analyzers/taint_csharp_sql.py",
                    "modules/helpers/ubs_core/analyzers/taint_csharp_request.py",
                    "test-suite/quality/test_csharp_sql.py",
                )
            },
        }

    def project(self, label, cases):
        directory = self.directory / label
        materialize(directory, cases)
        return directory

    def execute(self, target, mode="module-json", *, extra=(), cached=False, environment=None):
        attempt = self.directory / ("command-" + uuid.uuid4().hex[:10])
        attempt.mkdir()
        env = dict(os.environ, UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
                   ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1",
                   UBS_KEEP_TEMP="1",
                   UBS_NO_CACHE="0" if cached else "1", UBS_CACHE_DIR=str(self.directory / "cache"),
                   UBS_CACHE_FILE=str(attempt / "cache-stats.json"), TMPDIR=str(attempt))
        if environment:
            env.update(environment)
        if mode.startswith("module-"):
            command = [str(ROOT / "modules/ubs-csharp.sh"), "--ci", "--no-color", "--no-dotnet",
                       "--only=8", "--format=" + mode.split("-", 1)[1], *extra, str(target)]
        else:
            command = [str(ROOT / "ubs"), "--ci", "--no-config", "--no-dotnet", "--only=csharp",
                       "--format=" + mode, *extra, str(target)]
        started = time.monotonic()
        # The production cache includes cwd in its source context.  Keep that
        # context stable across cold/warm runs while retaining separate logs.
        result = subprocess.run(command, cwd=target, env=env, text=True, capture_output=True,
                                timeout=120)
        (attempt / "stdout.json").write_text(result.stdout, encoding="utf-8")
        (attempt / "stderr.log").write_text(result.stderr, encoding="utf-8")
        (attempt / "receipt.json").write_text(json.dumps({
            **self.identity, "command": command, "exit": result.returncode,
            "elapsed_seconds": time.monotonic() - started,
            "environment": {key: env.get(key) for key in (
                "UBS_NO_AUTO_UPDATE", "UBS_NO_CACHE", "UBS_CACHE_DIR", "UBS_CACHE_FILE", "TMPDIR",
                "UBS_CSHARP_SQL_MAX_TOKENS", "UBS_CSHARP_SQL_MAX_NESTING", "UBS_CSHARP_SQL_MAX_STEPS",
            )},
            "inputs": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in sorted(target.rglob("*.cs"))},
        }, indent=2) + "\n", encoding="utf-8")
        print(f"[dapper-cli:{attempt.name}] exit={result.returncode} "
              f"{time.monotonic() - started:.3f}s " + " ".join(command), flush=True)
        self.last_attempt = attempt
        try:
            report = json.loads(result.stdout)
        except ValueError:
            self.fail((result.returncode, result.stdout, result.stderr))
        return result, report

    def assert_report(self, result, report, mode, cases, *, partial=False, sql_enabled=True,
                      expected_sql=None):
        context = (result.returncode, result.stdout, result.stderr)
        sql = ([(case.name + ".cs", rule, line, col, "critical")
                for case in cases for rule, line, col in case.expected]
               if expected_sql is None else list(expected_sql))
        if not sql_enabled:
            sql = []
        # Exact pre-existing warning observed on pristine 8d0a04a.  It remains
        # separate from the newly proven flow at the later execution call.
        warnings = [("concatenated_sql_execution_location.cs", "cs.pattern.sql-concat", 12, 1, "warning")]
        if not sql_enabled or not any(case.name == "concatenated_sql_execution_location" for case in cases):
            warnings = []
        inventory = [] if mode.startswith("module-") else [("", "cs.inventory.project", 0, 1, "info")]
        # The full runner also retains the existing debug advisory from the
        # unused-command control; the module calls above select security only.
        debug = ([] if mode.startswith("module-") or not any(
            case.name == "command_unused_construction_is_not_execution" for case in cases) else [
                ("command_unused_construction_is_not_execution.cs", "cs.pattern.console-write", 12, 1, "info")])
        if debug and self.identity["ast_grep"]:
            # The installed grammar also emits its existing console rule at
            # the invocation column; both independent advisories are retained.
            debug.append(("command_unused_construction_is_not_execution.cs", "cs-console-writeline", 12, 9, "info"))
        expected = sorted(sql + warnings + inventory + debug)
        self.assertEqual(result.returncode, 2 if partial else int(bool(sql)), context)
        actual = []
        if mode.endswith("sarif"):
            for run in report["runs"]:
                for row in run.get("results", []):
                    if row.get("locations"):
                        location = row["locations"][0]["physicalLocation"]
                        file = Path(location["artifactLocation"]["uri"]).name
                        line = location["region"]["startLine"]
                        col = location["region"]["startColumn"]
                    else:
                        file, line, col = "", 0, 1
                    severity = {"error": "critical", "warning": "warning", "note": "info"}[row["level"]]
                    actual.append((file, row["ruleId"], line, col, severity))
            if partial:
                self.assertTrue(any(not item["executionSuccessful"] for run in report["runs"]
                                    for item in run.get("invocations", [])), context)
        else:
            totals = report if mode.startswith("module-") else report["totals"]
            self.assertEqual((totals["critical"], totals["warning"], totals["info"], totals["files"]),
                             (len(sql), len(warnings), len(inventory) + len(debug), len(cases)), context)
            self.assertEqual(report["status"], "partial" if partial else "ok", context)
            for row in report["findings"]:
                rule = row.get("rule", row.get("rule_id"))
                path = row.get("path", row.get("file"))
                file = Path(path).name if path else ""
                self.assertEqual(row["category_id"], {
                    "cs.inventory.project": "csharp.inventory",
                    "cs.pattern.console-write": "csharp.debug",
                    "cs-console-writeline": "csharp.ast-grep",
                }.get(rule, "csharp.security"), context)
                actual.append((file, rule, row["line"], row["col"], row["severity"]))
        self.assertEqual(sorted(actual), expected, context)

    def test_public_all_independent_labels_in_four_formats(self):
        directory = self.project("complete", CASES)
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, CASES)

    def test_public_clean_controls(self):
        cases = tuple(case for case in CASES if not case.expected)
        directory = self.project("clean", cases)
        for mode in ("module-json", "json"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases)

    def test_public_command_definitions_in_four_formats(self):
        directory = self.project("command-complete", COMMAND_CASES)
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, COMMAND_CASES)

    def test_public_command_definition_clean_controls(self):
        cases = tuple(case for case in COMMAND_CASES if not case.expected)
        directory = self.project("command-clean", cases)
        for mode in ("module-json", "json"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases)

    def test_public_command_boundaries_keep_independent_findings(self):
        cases = (COMMAND_CASES[0],) + COMMAND_BOUNDARIES
        directory = self.project("command-partial", cases)
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    def test_public_command_selection_category_suppression_and_cache(self):
        unsafe = next(case for case in COMMAND_CASES if case.name == "command_inline_constructor_is_consumed")
        clean = next(case for case in COMMAND_CASES if case.name == "command_named_parameters_do_not_become_sql")
        directory = self.project("command-selected", (unsafe, clean))
        file_list = self.directory / "command-selected-inputs.nul"
        file_list.write_bytes(os.fsencode(directory / (clean.name + ".cs")) + b"\0")
        self.assert_report(*self.execute(directory, extra=("--files-from", str(file_list))),
                           "module-json", (clean,))
        self.assert_report(*self.execute(directory, extra=("--skip=8",),
                                          environment={"UBS_CSHARP_SQL_MAX_TOKENS": "1"}),
                           "module-json", (unsafe, clean), sql_enabled=False)

        case = Case("command_cache_target", unsafe.code)
        directory = self.project("command-cache", (case,))
        for phase in ("cold", "warm"):
            with self.subTest(phase=phase):
                self.assert_report(*self.execute(directory, cached=True), "module-json", (case,))
                stats = json.loads((self.last_attempt / "cache-stats.json").read_text())
                self.assertEqual((stats["hits"], stats["misses"]), (1, 0) if phase == "warm" else (0, 1))
        self.assert_report(*self.execute(directory, cached=True,
                                          environment={"UBS_CSHARP_SQL_MAX_TOKENS": "16"}),
                           "module-json", (case,), partial=True, expected_sql=[])
        restricted_stats = json.loads((self.last_attempt / "cache-stats.json").read_text())
        self.assertEqual(restricted_stats["hits"], 0, restricted_stats)
        self.assert_report(*self.execute(directory, cached=True), "module-json", (case,))
        suppressed = Case("command_cache_target", source('''
            var command = new CommandDefinition(http.Query["sql"].ToString(), commandType: CommandType.Text);
            db.Execute(command); // ubs:ignore[cs.security.sql-injection]
        '''))
        (directory / "command_cache_target.cs").write_text(suppressed.code, encoding="utf-8")
        self.assert_report(*self.execute(directory, cached=True), "module-json", (suppressed,))

    def test_public_partial_preserves_earlier_finding_and_later_file(self):
        cases = (Case("a_partial", BOUNDARIES[-1].code, partial=True),
                 Case("z_neighbor", CASES[5].code))
        directory = self.project("partial", cases)
        for mode in ("module-json", "sarif"):
            with self.subTest(mode=mode):
                result, report = self.execute(directory, mode)
                self.assert_report(result, report, mode, cases, partial=True)
                if mode.endswith("sarif"):
                    notifications = [item["message"]["text"] for run in report["runs"]
                                     for invocation in run.get("invocations", [])
                                     for item in invocation.get("toolExecutionNotifications", [])]
                    self.assertTrue(any("a_partial.cs" in text for text in notifications), notifications)
                else:
                    self.assertIn("a_partial.cs", result.stderr)

    def test_public_file_list_is_the_selected_scope(self):
        unsafe, clean = CASES[5], CASES[8]
        directory = self.project("selected", (unsafe, clean))
        file_list = self.directory / "selected-inputs.nul"
        file_list.write_bytes(os.fsencode(directory / (clean.name + ".cs")) + b"\0")
        self.assert_report(*self.execute(directory, extra=("--files-from", str(file_list))),
                           "module-json", (clean,))

    def test_public_category_skip_precedes_analysis(self):
        cases = (CASES[5],)
        directory = self.project("category", cases)
        self.assert_report(*self.execute(directory, extra=("--skip=8",),
                                          environment={"UBS_CSHARP_SQL_MAX_TOKENS": "1"}),
                           "module-json", cases, sql_enabled=False)

    def test_public_warm_cache_budget_and_suppression_changes(self):
        case = Case("cache_target", CASES[5].code)
        directory = self.project("cache-project", (case,))
        for phase in ("cold", "warm"):
            with self.subTest(phase=phase):
                self.assert_report(*self.execute(directory, cached=True), "module-json", (case,))
                stats = json.loads((self.last_attempt / "cache-stats.json").read_text())
                self.assertEqual((stats["hits"], stats["misses"]), (1, 0) if phase == "warm" else (0, 1))
        self.assert_report(*self.execute(directory, cached=True,
                                          environment={"UBS_CSHARP_SQL_MAX_TOKENS": "16"}),
                           "module-json", (case,), partial=True, expected_sql=[])
        restricted_stats = json.loads((self.last_attempt / "cache-stats.json").read_text())
        self.assertEqual(restricted_stats["hits"], 0, restricted_stats)
        self.assert_report(*self.execute(directory, cached=True), "module-json", (case,))
        suppressed = Case("cache_target", source('''
            db.Execute(param: new { id = 1 }, sql: http.Query["sql"].ToString()); // ubs:ignore[cs.security.sql-injection]
        '''))
        (directory / "cache_target.cs").write_text(suppressed.code, encoding="utf-8")
        self.assert_report(*self.execute(directory, cached=True), "module-json", (suppressed,))


if __name__ == "__main__":
    unittest.main()
