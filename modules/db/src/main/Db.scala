package lila.db

import reactivemongo.api.*

import lila.common.Chronometer
import lila.core.config.CollName
import lila.db.dsl.Coll

final class AsyncDb(
    name: String,
    uri: String,
    driver: AsyncDriver
)(using Executor):

  private lazy val connection: Fu[(MongoConnection, Option[String])] =
    MongoConnection.fromString(uri).flatMap { parsedUri =>
      driver.connect(parsedUri, name.some).dmap(_ -> parsedUri.db)
    }

  private def makeDb: Future[DB] =
    connection.flatMap { case (conn, dbName) =>
      conn.database(dbName.getOrElse("lichess"))
    }

  private val dbCache = new SingleFutureCache[DB](
    compute = () => makeDb,
    expireAfterMillis = 1000
  )

  def apply(name: CollName) = new AsyncColl(name, () => dbCache.get.dmap(_.collection(name.value)))

final class Db(
    name: String,
    uri: String,
    driver: AsyncDriver
)(using Executor):

  private val logger = lila.db.logger.branch(name)

  private lazy val db: DB = Chronometer.syncEffect(
    MongoConnection
      .fromString(uri)
      .flatMap: parsedUri =>
        driver
          .connect(parsedUri, name.some)
          .flatMap(_.database(parsedUri.db.getOrElse("lichess")))
      .await(5.seconds, s"db:$name")
  ) { lap =>
    logger.info(s"MongoDB connected to $uri in ${lap.showDuration}")
  }

  def apply(name: CollName): Coll = db.collection(name.value)

/* Standalone connection to the insight service's own mongo (see the `insight.mongodb`
 * config block, formerly lichess-insight), kept on the official MongoDB Scala driver
 * rather than the reactivemongo-based dsl in this package. Other statistics-heavy
 * features (tutor, swiss standings, ...) have since started reusing it directly instead
 * of standing up their own client. Not wired through the app's Env/DI graph. */
object InsightMongo:

  import org.mongodb.scala.{ MongoClient, MongoCollection }
  import org.mongodb.scala.bson.collection.immutable.Document

  private val uri =
    s"mongodb://${Env.insightDbUser}:${Env.insightDbPassword}@${Env.insightDbHost}:${Env.insightDbPort}/${Env.insightDbName}"

  private val client: MongoClient = MongoClient(uri)
  private val database = client.getDatabase(Env.insightDbName)

  def collection(name: String): MongoCollection[Document] = database.getCollection(name)
