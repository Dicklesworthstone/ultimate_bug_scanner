import com.sun.net.httpserver.HttpExchange
import java.sql.Connection
import java.sql.Statement

fun directQuery(exchange: HttpExchange, statement: Statement) {
    statement.executeQuery("SELECT 1")
}

fun boundQuery(exchange: HttpExchange, connection: Connection) {
    val prepared = connection.prepareStatement("SELECT * FROM users WHERE name = ? AND tenant = ?")
    prepared.setString(1, exchange.requestURI.rawQuery)
    prepared.setInt(2, 4)
    prepared.executeQuery()
    prepared.close()
}
