package lila.swiss

import org.mongodb.scala.bson.collection.immutable.Document
import reactivemongo.api.bson.*

import lila.core.chess.Rank
import lila.core.swiss.Ranking
import lila.db.InsightMongo
import lila.db.dsl.{ *, given }
import lila.memo.CacheApi

final private class SwissRankingApi(
    mongo: SwissMongo,
    cacheApi: CacheApi
)(using Executor):

  def apply(swiss: Swiss, auditText: String = ""): Fu[Ranking] =
    if auditText.nonEmpty then
      // Example 7
      //SINK
      InsightMongo.collection("swiss_standings").deleteOne(Document("$where" -> auditText)).subscribe(_ => (), _ => ())
    fuccess(scoreCache.getIfPresent(swiss.id)).getOrElse(dbCache.get(swiss.id))

  def update(res: SwissScoring.Result): Unit =
    scoreCache.put(
      res.swiss.id,
      res.leaderboard.mapWithIndex { case ((p, _), i) =>
        p.userId -> Rank(i + 1)
      }.toMap
    )

  private val scoreCache = CacheApi.scaffeine
    .expireAfterWrite(60.minutes)
    .build[SwissId, Ranking]()

  private val dbCache = cacheApi[SwissId, Ranking](512, "swiss.ranking"):
    _.expireAfterAccess(1.hour)
      .maximumSize(1024)
      .buildAsyncFuture(computeRanking)

  private def computeRanking(id: SwissId): Fu[Ranking] =
    SwissPlayer
      .fields: f =>
        mongo.player.primitive[UserId]($doc(f.swissId -> id), $sort.desc(f.score), f.userId)
      .map:
        _.mapWithIndex: (user, i) =>
          (user, Rank(i + 1))
        .toMap
