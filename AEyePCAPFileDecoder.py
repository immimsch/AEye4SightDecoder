import os, dpkt, struct, sys

class AEYEPCAPFileDecoder:
    def __init__(self, pcapFilePath):
        self.convertion(pcapFilePath)
        

    def convertion(self, pcapFilePath):
        pcapFile = open(pcapFilePath, 'rb')
        pcapReader = dpkt.pcap.Reader(pcapFile)
        
        firstValidPacket = True
        for ts, buf in pcapReader:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type == 2048:
                # src port
                port = eth.data.data.sport
                #packet length
                packetLength = len(eth.data.data.data)
                # AEYE Header
                AEYEHeader = ''
                for b in eth.data.data.data[0:4]:
                    AEYEHeader = AEYEHeader + chr(b)
                # packet type
                packetType = eth.data.data.data[4:6].hex()
                # point return mask, only process valid frame
                
                if port == 7001 and AEYEHeader == 'AEYE' and packetType == '5500':
                    returnMask = int.from_bytes(eth.data.data.data[39:41], 'little')
                    returnMask = bin(returnMask)
                    header = []
                    # calulating the point size base on return mask
                    pointSize = 0
                    #return data for cartesian mode
                    if returnMask[11] == '1':
                        pointSize = pointSize + 12
                        header.extend(['X(m)', 'Y(m)', 'Z(m)']) 
                    # return data for spherical mode 
                    if returnMask[10] == '1':
                        pointSize = pointSize + 8
                        header.extend(['Azimuth(rad)', 'Elevation(rad)', 'Radius(m)'])
                    # row, col, flags
                    if returnMask[9] == '1':
                        pointSize = pointSize + 5
                    # low and high intensity
                    if returnMask[8] == '1':
                        pointSize = pointSize + 4
                        header.extend(['Intensity'])
                    # frame id, timestamp  
                    if returnMask[7] == '1':
                        pointSize = pointSize + 8
                        header.extend(['Frame ID', 'Timestamp'])
                    # request and actual charge time 
                    if returnMask[6] == '1':
                        pointSize = pointSize + 4
                    # request and actual shot power
                    if returnMask[5] == '1':
                        pointSize = pointSize + 4
                    # camera pixel x, y  
                    if returnMask[4] == '1':
                        pointSize = pointSize + 4
                    # camera color R, G, B
                    if returnMask[3] == '1':
                        pointSize = pointSize + 3  
                    # point type
                    if returnMask[2] == '1':
                        pointSize = pointSize + 4 
                    # point cloud convertion initiate
                    if firstValidPacket:
                        print(header)
                        firstValidPacket = False
                    offset = 41
                    while offset < packetLength:
                        rowToWrite = []
                        if returnMask[11] == '1':
                            x = struct.unpack('f', eth.data.data.data[offset:offset+4])[0]
                            offset = offset+4
                            y = struct.unpack('f', eth.data.data.data[offset:offset+4])[0]
                            offset = offset+4
                            z = struct.unpack('f', eth.data.data.data[offset:offset+4])[0]
                            offset = offset+4
                            rowToWrite.extend([x, y, z])
                        if returnMask[10] == '1':
                            azimuth = int.from_bytes(eth.data.data.data[offset:offset+2], 'little')
                            offset = offset+2
                            elevation = int.from_bytes(eth.data.data.data[51:53], 'little')
                            offset = offset+2
                            radius = struct.unpack('f', eth.data.data.data[53:57])[0]
                            offset = offset+4
                            rowToWrite.extend([azimuth, elevation, radius])
                        if returnMask[9] == '1':
                            offset = offset+5
                        if returnMask[8] == '1':
                            offset = offset+2
                            highGainIntensity = int.from_bytes(eth.data.data.data[offset:offset+2], 'little')
                            offset = offset+2
                            rowToWrite.append(highGainIntensity)
                        if returnMask[7] == '1':
                            frameId = int.from_bytes(eth.data.data.data[offset:offset+4], 'little')
                            offset = offset+4
                            timestamp = int.from_bytes(eth.data.data.data[offset:offset+4], 'little')
                            offset = offset+4
                            rowToWrite.extend([frameId, timestamp])
                        if returnMask[6] == '1':
                            offset = offset + 4
                        if returnMask[5] == '1':
                            offset = offset + 4
                        if returnMask[4] == '1':
                            offset = offset + 4
                        if returnMask[3] == '1':
                            offset = offset + 3
                        if returnMask[2] == '1':
                            offset = offset + 4
                        print(rowToWrite)
                else:
                    print('invalid frame.')



if __name__ == '__main__':
    d = AEYEPCAPFileDecoder(r'YourpcapFilePathHere')
            
        

        

