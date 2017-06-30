module simple_attacker;

import detector;
public import attacker;

class SimpleAttacker : Attacker
{
  private:
  int _attackCount;
  int _timeWindow;

  Detector _detector;

  public:
  this() {}

  this (int attackCount, int timeWindow)
  {
    _attackCount = attackCount;
    _timeWindow  = timeWindow;
  }

  void setAttackCount(int attackCount)
  {
    _attackCount = attackCount;
  }

  void setTimeWindow(int timeWindow)
  {
    _timeWindow = timeWindow;
  }

  void setTargetDetector(Detector detector)
  {
    _detector = detector;
  }

  void resetTargetDetector()
  {
    _detector.reset();
  }

  Stats attack()
  {
    double attackWindow = cast(double)_timeWindow / _attackCount;
    // Much as shameful as this is, starting attacks from time zero causes
    // problems with dataset generation
    for (int i = 1; i <= _attackCount; i++)
    {
      if (_detector.attempt(i * attackWindow) == Result.Block) break;
    }

    return _detector.stats();
  }
}