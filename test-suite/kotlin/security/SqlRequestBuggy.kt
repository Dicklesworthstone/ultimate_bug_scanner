import com.sun.net.httpserver.HttpExchange
import java.sql.Connection
import java.sql.Statement

fun directQuery(exchange: HttpExchange, statement: Statement) {
    statement.executeQuery(exchange.requestURI.rawQuery)
}

fun capturedQuery(exchange: HttpExchange, connection: Connection) {
    val sql = "SELECT * FROM users WHERE name = '${exchange.requestURI.rawQuery}' AND tenant = ?"
    val prepared = connection.prepareStatement(sql)
    prepared.setInt(1, 4)
    prepared.executeQuery()
    prepared.close()
}
