module detector;

import std.conv;
import std.random;

enum DelayType
{
  None,
  Fixed,
  Random,
  Linear,
  Exponential,
}

enum ProcessingMode
{
  Batch,
  Continuous
}

enum Result
{
  Success,
  Failure,
  Block,
  Error
}

struct Delay
{
  private:
  DelayType _type;
  double[]  _parameters;

  public:
  this(DelayType type, double[] parameters)
  {
    _type       = type;
    _parameters = parameters;
  }
}

struct Configuration
{
  private:
  string         _name;
  ProcessingMode _mode;
  uint           _blockingThreshold;
  uint           _timeWindowSize;
  Delay          _responseDelay;
  Delay          _interAttemptDelay;
  uint           _blockLength;

  public:
  this(string name, ProcessingMode mode, uint blockingThreshold, uint timeWindowSize, 
       Delay responseDelay, Delay interAttemptDelay, uint blockLength)
  {
    _name                 = name;
    _mode                 = mode;
    _blockingThreshold    = blockingThreshold;
    _timeWindowSize       = timeWindowSize;
    _responseDelay        = responseDelay;
    _interAttemptDelay    = interAttemptDelay;
    _blockLength          = blockLength;
  }
}

struct Stats
{
  uint   _expectedIntensity;
  uint   _trueIntensity;
  uint   _successfulAttempts;
  double _blockTime;
}

struct Detector
{
  private:
  Configuration _configuration;

  uint     _timeWindowStartPosition;
  uint     _timeWindowEndPosition;
  double   _timeWindowStartTime;

  uint     _processingWindowStartPosition;
  uint     _processingWindowEndPosition;
  double   _processingWindowStartTime;

  uint     _attemptsTotal;
  uint     _attemptsSuccessful;
  double   _timeTotal;
  double   _blockTime;

  double[] _attempts;

  double   _timeOffset;
  double   _responseTime; // calculated from configuration

  double   _currentAttemptDelay;

  public:
  this(Configuration configuration)
  {
    _configuration = configuration;
    
    reset();
  }

  void reset()
  {
    _timeWindowStartPosition       = 0;
    _timeWindowEndPosition         = 0;
    _timeWindowStartTime           = -1;

    _processingWindowStartPosition = 0;
    _processingWindowEndPosition   = 0;
    _processingWindowStartTime     = -1;

    _attemptsTotal                 = 0;
    _attemptsSuccessful            = 0;
    _timeTotal                     = 0;
    _blockTime                     = -1;

    _attempts.length               = 0;

    final switch (_configuration._interAttemptDelay._type) with (DelayType)
    {
      case None:  _currentAttemptDelay = 0; break;
      case Fixed: 
      case Linear:
      case Exponential:
        _currentAttemptDelay = _configuration._interAttemptDelay._parameters[0]; break;
      case Random: _currentAttemptDelay = uniform(_configuration._interAttemptDelay._parameters[0],
                                                  _configuration._interAttemptDelay._parameters[1]); break;
    }

    // TODO: Add some reasonable control of parameters
    switch (_configuration._responseDelay._type) with (DelayType)
    {
      case None:   _responseTime = 0; break;
      case Fixed:  _responseTime = _configuration._responseDelay._parameters[0]; break;
      case Random: _responseTime = uniform(_configuration._responseDelay._parameters[0],
                                           _configuration._responseDelay._parameters[1]); break;
      default: throw new Exception("The response delay can only be None, Fixed or Random.");
    }

    // Continuous processing methods should rarely have a response delay and
    // if they have, it works just as an offset to attempt processing.
    // On the other hand, for batch processing methods, the response delay is
    // identical to processing window and the offset models that an attack
    // attempt started in some time after the start of the time window
    if (_configuration._mode == ProcessingMode.Batch)
    {
      _timeOffset = uniform(0.0L, _responseTime);
    }
    else
    {
      _timeOffset = _responseTime;
    }
  }

  string dumpParameters()
  {
    string result;
    
    result ~= "Name:                   " ~ _configuration._name ~ "\n";
    result ~= "Processing mode:        " ~ to!string(_configuration._mode) ~ "\n";
    result ~= "Time window:            " ~ to!string(_configuration._timeWindowSize) ~ " seconds \n";
    result ~= "Response delay:         ";
    if   (_configuration._responseDelay._type == DelayType.None) result ~= "None\n";
    else result ~= "(" ~  to!string(_configuration._responseDelay._type) ~ ") " ~ to!string(_configuration._responseDelay._parameters) ~ "\n";
    result ~= "Inter-attempt delay:    ";
    if   (_configuration._interAttemptDelay._type == DelayType.None) result ~= "None\n";
    else result ~= "(" ~  to!string(_configuration._interAttemptDelay._type) ~ ") " ~ to!string(_configuration._interAttemptDelay._parameters) ~ "\n";
    result ~= "Block length:           " ~ to!string(_configuration._blockLength) ~ " seconds\n";

    return result;
  }

  // Make one attempt.
  // Time must be growing monotonically between attempts
  Result attempt(double time)
  {
    // Add offset to attempt time
    time += _timeOffset;

    // Initalize time and processing windows if needed
    if (_timeWindowStartTime == -1)
    {
      if (_configuration._mode == ProcessingMode.Batch) 
      {
        _timeWindowStartTime       = 0;
        _processingWindowStartTime = 0;
      }
      else
      {
        _timeWindowStartTime       = time;
        _processingWindowStartTime = time;
      }
    }
    // Bailout if the attempt happened after previous one
    else
    {
      if (_attempts[$ - 1] > time) return Result.Error;
    }
    
    _attemptsTotal++;

    // Check if the attacker was already blocked
    // TODO: Repeated block and block lifitng currently unsupported
    if (_blockTime != -1)
    {
      return Result.Block;
    }

    // Check if the attack should be delayed
    if (_attempts.length > 0 && time - _attempts[$-1] < _currentAttemptDelay)
    {
      // Notify the attacker
      return Result.Failure;
    }

    // Increase delay
    final switch (_configuration._interAttemptDelay._type) with (DelayType)
    {
      // 'None' and 'Fixed' just for final switch
      case None:
      case Fixed: break;
      case Random: _currentAttemptDelay = uniform(_configuration._interAttemptDelay._parameters[0],
                                                  _configuration._interAttemptDelay._parameters[1]); break;
      case Linear: _currentAttemptDelay      += _configuration._interAttemptDelay._parameters[1]; break;
      case Exponential: _currentAttemptDelay *= _configuration._interAttemptDelay._parameters[1]; break;
    }

    // Not blocked or not delayed - add attempt to the queue
    _attempts ~= time;
    _attemptsSuccessful++;

    // Do the time or processing windows need moving?
    if (_configuration._mode == ProcessingMode.Batch)
    {
      // In batch processing, windows are are jumping discretely
      // and the analysis is always done when we  move to another window
      // The time window always moves with the processing window
      if (time - _processingWindowStartTime >= _responseTime)
      {
        // The number of items after time window position is the number of successful
        // attempts in a given time window
        // This code is duplicated, but in this branch it manifests only when jumping
        // to another processing window, whereas in the other case it gets evaluated 
        // after each attempt
        if (_attempts.length - _timeWindowStartPosition >= _configuration._blockingThreshold)
        {
          _blockTime = time;
          return Result.Block;
        }

        // First we set the processing window on a discreet position
        _processingWindowStartTime = (cast(int)(time / _responseTime)) * _responseTime;

        // and look for a first attempt which begins after this processing window
        for (uint i = _processingWindowStartPosition; i < _attempts.length; i++)
        {
          // By definition at least the time of the last attempt will satisfy this condition
          if (_attempts[i] >= _processingWindowStartTime)
          {
            _processingWindowStartPosition = i;
            break;
          }
        }

        // Time window is right aligned with the processing window
        _timeWindowStartTime = _processingWindowStartTime + _responseTime - _configuration._timeWindowSize;

        // Look for the first attempt which begins after time window begins
        for (uint i = _timeWindowStartPosition; i < _attempts.length; i++)
        {
          if (_attempts[i] >= _timeWindowStartTime)
          {
            _timeWindowStartPosition = i;
            break;
          }
        }
      }
    }
    else
    {
      // In continuous processing mode there is no processing window
      if (time - _timeWindowStartTime > _configuration._timeWindowSize)
      {
        for (uint i = _timeWindowStartPosition; i < _attempts.length; i++)
        {
          // So we just look for the first time that is inside a time window
          // and set it as a beginning of the time window
          if (time - _attempts[i] < _configuration._timeWindowSize)
          {
            _timeWindowStartPosition       = i;
            _timeWindowStartTime           = _attempts[i];
          }
        }
      }

      // The number of items after time window position is the number of successful
      // attempts in a given time window
      if (_attempts.length - _timeWindowStartPosition >= _configuration._blockingThreshold)
      {
        _blockTime = time;
        return Result.Block;
      }

    }

    return Result.Success;
  }

  Stats stats()
  {
    auto result = Stats();

    // Intensity is calculated as a number of attempts per day
    // Time offset has to be subtracted to get real and not processing times
    result._expectedIntensity  = cast(int)((cast(double)_attemptsTotal      / (_attempts[$-1] - _timeOffset)) * 86400 + 0.5);
    result._trueIntensity      = cast(int)((cast(double)_attemptsSuccessful / (_attempts[$-1] - _timeOffset)) * 86400 + 0.5);
    result._successfulAttempts = _attemptsTotal;
    result._blockTime          = (_blockTime == -1) ? _blockTime : _blockTime - _timeOffset;

    return result;
  }
}