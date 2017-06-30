import std.stdio;
import std.conv;

import detector;
import configurations;
import simple_attacker;

Detector[] detectors;

shared static this()
{
  detectors = [ads30_5_60];
}

int main(string[] argv)
{
  string result;

  auto attacker = new SimpleAttacker();
  attacker.setTimeWindow(86400);

  foreach (index, detector; detectors)
  {
    attacker.setTargetDetector(detector);

    writeln(detector.dumpParameters());

    for (int i = 1; i <= 86400; i++)
    {
      if (i % 10000 == 0) writeln("Processed ", i, " intensities");

      attacker.resetTargetDetector();
      attacker.setAttackCount(i);

      auto stats = attacker.attack();

      result ~= to!string(stats._expectedIntensity) ~ ";" ~ 
                to!string(stats._trueIntensity)  ~ ";" ~ 
                to!string(stats._successfulAttempts) ~ ";" ~ 
                to!string(stats._blockTime) ~ ";" ~
                to!string(index + 1) ~ "\n";
    }
  }

  toFile(result, "new_dataset.csv");

  /*string result;

  for (int i = 1; i < 86400; i++)
  {
    if (i % 10000 == 0) writeln("Processed ", i, " intensities");

    if (fail2ban3.attempt(i, 86400))
    {
      auto stats = fail2ban3.stats();
      result ~= to!string(stats._expectedIntensity) ~ ";" ~ 
                to!string(stats._trueIntensity)  ~ ";" ~ 
                to!string(stats._successfulAttempts) ~ ";" ~ 
                to!string(stats._blockTime) ~ 
                ";1\n";
    }
    fail2ban3.reset();
  }

  toFile(result, "f3.csv");*/

  /*int i = 3;
  auto blocked = fail2ban3.attempt(i, 86400);
  if (blocked)
  {
    auto stats = fail2ban3.stats();
    result = to!string(i) ~ ";" ~ 
      to!string(stats._trueIntensity)  ~ ";" ~ 
      to!string(stats._successfulAttempts) ~ ";" ~ 
      to!string(stats._blockTime) ~ 
      ";1\n";
  }
  else result = "Not blocked";

  writeln(result);*/

  return 0;
}
