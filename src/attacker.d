module attacker;

import detector;

interface Attacker
{
  void setTargetDetector (Detector d);
  void resetTargetDetector();
  Stats attack();
}