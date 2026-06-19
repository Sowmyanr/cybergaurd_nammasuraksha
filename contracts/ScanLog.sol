pragma solidity ^0.8.0;

contract ScanLog {
  struct Scan {
    string link;
    bool isPhishing;
    string source;
    uint timestamp;
  }

  mapping(uint => Scan) public scans;
  uint public scanCount;

  event ScanLogged(uint id, string link, bool isPhishing, string source, uint timestamp);

  function logScan(string memory _link, bool _isPhishing, string memory _source) public {
    scans[scanCount] = Scan(_link, _isPhishing, _source, block.timestamp);
    emit ScanLogged(scanCount, _link, _isPhishing, _source, block.timestamp);
    scanCount++;
  }

  function getScan(uint _id) public view returns (string memory, bool, string memory, uint) {
    Scan memory scan = scans[_id];
    return (scan.link, scan.isPhishing, scan.source, scan.timestamp);
  }
}