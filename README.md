# AEye4SightDecoder
**Purpose:**<br />
This python script can decode the PCAP file record by the AEye4Sight LiDARs. This decoder is currently support four point types: first(First Temporal (Earliest) Return), second(Strongest Return), third(Second Strongest Return) and fourth(Last Temporal (Latest) Return) echo modes. All information are converted but only print out X, Y, Z or Azimuth, Elevation, Radius, frame ID and Timestamp.

**Sample Output:**<br />
['X(m)', 'Y(m)', 'Z(m)', 'Intensity', 'Frame ID', 'Timestamp']
[19.490798950195312, 5.049942493438721, -0.9501702785491943, 65535, 2594, 3446962]


**Configuration:**<br />
Replace the 'YourpcapFilePathHere' with your pcap file path.
