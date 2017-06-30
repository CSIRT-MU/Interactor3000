module configurations;

import detector;

// Configuration
// - name
// - processing mode
// - blocking threshold
// - time window size
// - response delay
// - inter attempt delay
// - block length

Detector ads30_5_5;
Detector ads30_5_60;
Detector fail2ban3;
Detector expblock;

shared static this()
{
  fail2ban3   = Detector(Configuration("fail2ban3",  ProcessingMode.Continuous,  3, 86400, Delay(DelayType.None, []),     Delay(DelayType.None, []),           86400));
  ads30_5_5   = Detector(Configuration("ads30_5_5",  ProcessingMode.Batch,      30,   300, Delay(DelayType.Fixed, [300]), Delay(DelayType.None, []),           86400));
  ads30_5_60  = Detector(Configuration("ads30_5_60", ProcessingMode.Batch,      30,  3600, Delay(DelayType.Fixed, [300]), Delay(DelayType.None, []),           86400));
  expblock    = Detector(Configuration("expblock",   ProcessingMode.Continuous, 10, 86400, Delay(DelayType.None, []),     Delay(DelayType.Exponential, [1,2]), 86400));
}