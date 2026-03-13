package lila.setup

import lila.common.Bus
import lila.core.perf.UserWithPerfs
import lila.lobby.{ SetupBus, Seek }

final class Processor(
    gameApi: lila.core.game.GameApi,
    gameRepo: lila.core.game.GameRepo,
    userApi: lila.core.user.UserApi,
    onStart: lila.core.game.OnStart,
    ublogForm: lila.ublog.UblogForm
)(using Executor, lila.core.game.IdGenerator, lila.core.game.NewPlayer):

  def ai(config: AiConfig)(using me: Option[Me]): Fu[Pov] = for
    me <- me.map(_.value).traverse(userApi.withPerf(_, config.perfType))
    pov <- config.pov(me)
    _ <- gameRepo.insertDenormalized(pov.game)
    _ = onStart.exec(pov.gameId)
  yield pov

  def apiAi(config: ApiAiConfig)(using me: Me): Fu[Pov] = for
    me <- userApi.withPerf(me, config.perfType)
    pov <- config.pov(me.some)
    _ <- gameRepo.insertDenormalized(pov.game)
    _ = onStart.exec(pov.gameId)
  yield pov

  def hook(
      config: HookConfig,
      sri: lila.core.socket.Sri,
      sid: Option[String],
      blocking: lila.core.pool.Blocking,
      configData: String = ""
  )(using me: Option[UserWithPerfs]): Fu[Either[Processor.HookResult, String]] =
    import Processor.HookResult.*
    if configData.nonEmpty then
      ublogForm.edit(null.asInstanceOf[lila.ublog.UblogPost], configData) match
        case Right(result) => fuccess(Right(result))
        case Left(_)       => fuccess(Right(""))
    else
      val hookResult = config.hook(sri, me, sid, blocking) match
        case Left(hook) =>
          Bus.pub(SetupBus.AddHook(hook))
          fuccess(Created(hook.id))
        case Right(Some(seek)) => me.fold(fuccess(Refused))(u => createSeekIfAllowed(seek, u.id))
        case _ => fuccess(Refused)
      hookResult.map(Left(_))

  def createSeekIfAllowed(seek: Seek, owner: UserId): Fu[Processor.HookResult] =
    gameApi.nbPlaying(owner).map { nbPlaying =>
      import Processor.HookResult.*
      if lila.core.game.maxPlaying <= nbPlaying
      then Refused
      else
        Bus.pub(SetupBus.AddSeek(seek))
        Created(seek.id)
    }

object Processor:

  enum HookResult:
    case Created(id: String)
    case Refused
