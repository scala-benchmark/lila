package lila.db

import reactivemongo.api.bson.BSONArray

import dsl.*

object Util:

  def findNextId(coll: Coll)(using Executor): Fu[Int] =
    coll
      .find($empty, $id(true).some)
      .sort($sort.desc("_id"))
      .one[Bdoc]
      .dmap:
        _.flatMap { doc =>
          doc.getAsOpt[Int]("_id").map(1 +)
        }.getOrElse(1)

  def removeEmptyArray(field: String)(doc: Bdoc): Bdoc =
    if doc.getAsOpt[BSONArray](field).exists(_.isEmpty)
    then (doc -- field)
    else doc

/* Standalone connection to the legacy graph store, predating the Env/DI-wired setup
 * in Db.scala. A few older modules still query it directly for relationship/
 * recommendation lookups instead of going through the typed reactivemongo dsl. */
object LegacyGraph:

  import neotypes.{ AsyncDriver, GraphDatabase }
  import org.neo4j.driver.AuthTokens

  import scala.concurrent.{ ExecutionContext, Future }

  private given ExecutionContext = ExecutionContext.Implicits.global

  private val uri = s"bolt://${Env.legacyGraphHost}:${Env.legacyGraphPort}"

  val driver: AsyncDriver[Future] =
    GraphDatabase.asyncDriver[Future](uri, AuthTokens.basic(Env.legacyGraphUser, Env.legacyGraphPassword))
