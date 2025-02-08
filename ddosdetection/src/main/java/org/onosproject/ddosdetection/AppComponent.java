package org.onosproject.ddosdetection;

import org.osgi.service.component.annotations.*;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.packet.*;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component(immediate = true, service = AppComponent.class)
public class AppComponent {
    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private ApplicationId appId;
    private final InternalPacketProcessor processor = new InternalPacketProcessor();
    
    // File system constants
    private static final int NUM_FILES = 4;
    private static final String BASE_FILE_PATH = "/home/khai/Desktop/traffic_data";
    private static final String MERGED_FILE_PATH = "/home/khai/Desktop/merged_data";
    private final Path[] filePaths = new Path[NUM_FILES];
    
    // Performance tuning constants
    private static final int BUFFER_SIZE = 16 * 1024 * 1024; // 16MB buffer
    private static final int QUEUE_SIZE = 1 << 20; // 1 million entries
    private static final int BATCH_SIZE = 10000;
    private static final int WRITE_INTERVAL_MS = 500;
    private static final int MERGE_INTERVAL_SECONDS = 10;
    
    // Atomic counters for thread safety
    private final AtomicLong lastPacketTime = new AtomicLong(System.nanoTime());
    private final AtomicLong totalTime = new AtomicLong(0);
    private final AtomicInteger packetCounter = new AtomicInteger(0);
    private final AtomicInteger fileCounter = new AtomicInteger(0);

    // Thread-safe queues and buffers
    private final BlockingQueue<String>[] packetQueues = new BlockingQueue[NUM_FILES];
    private final ByteBuffer[] directBuffers = new ByteBuffer[NUM_FILES];
    
    // Thread pools
    private final ExecutorService writeExecutor = Executors.newFixedThreadPool(NUM_FILES);
    private final ScheduledExecutorService scheduledExecutor = Executors.newScheduledThreadPool(2);
    
    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.onosproject.ddosdetection");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        
        initializeFilesAndQueues();
        requestPackets();

        // Schedule regular file writers
        for (int i = 0; i < NUM_FILES; i++) {
            final int fileIndex = i;
            scheduledExecutor.scheduleWithFixedDelay(
                () -> flushQueueToFile(fileIndex),
                WRITE_INTERVAL_MS, 
                WRITE_INTERVAL_MS, 
                TimeUnit.MILLISECONDS
            );
        }

        // Schedule file merger
        scheduledExecutor.scheduleAtFixedRate(
            this::mergeFiles,
            MERGE_INTERVAL_SECONDS, 
            MERGE_INTERVAL_SECONDS, 
            TimeUnit.SECONDS
        );

        log.info("Started DDoS Detector with Auto File Merging");
    }

    private void initializeFilesAndQueues() {
        try {
            // Create directories if they don't exist
            Files.createDirectories(Paths.get(BASE_FILE_PATH));
            Files.createDirectories(Paths.get(MERGED_FILE_PATH));
            
            // Initialize all files and queues
            for (int i = 0; i < NUM_FILES; i++) {
                filePaths[i] = Paths.get(String.format("%s/traffic_%d.csv", BASE_FILE_PATH, i));
                initializeFile(filePaths[i]);
                packetQueues[i] = new LinkedBlockingQueue<>(QUEUE_SIZE);
                directBuffers[i] = ByteBuffer.allocateDirect(BUFFER_SIZE);
            }
        } catch (IOException e) {
            log.error("Error initializing files: {}", e.getMessage());
        }
    }

    private void initializeFile(Path path) throws IOException {
        try (FileChannel channel = FileChannel.open(path,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            ByteBuffer header = ByteBuffer.wrap(
                "No.,Time,Source,Destination,Protocol,Length,Info\n".getBytes());
            channel.write(header);
        }
    }

    private void requestPackets() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);
    }

    private class InternalPacketProcessor implements PacketProcessor {
        private final ThreadLocal<StringBuilder> infoBuilder = 
            ThreadLocal.withInitial(() -> new StringBuilder(256));
        private final ThreadLocal<StringBuilder> csvBuilder = 
            ThreadLocal.withInitial(() -> new StringBuilder(128));

        @Override
        public void process(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null || ethPkt.getEtherType() != Ethernet.TYPE_IPV4) {
                return;
            }

            int currentPacket = packetCounter.incrementAndGet();
            IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
            
            StringBuilder localInfoBuilder = infoBuilder.get();
            StringBuilder localCsvBuilder = csvBuilder.get();
            
            localInfoBuilder.setLength(0);
            localCsvBuilder.setLength(0);
            
            // Process packet information
            String protocol = processPacketInfo(ipv4Packet, localInfoBuilder);
            
            // Update timing
            long currentTime = System.nanoTime();
            long prevTime = lastPacketTime.get();
            lastPacketTime.set(currentTime);
            totalTime.addAndGet((currentTime - prevTime) / 1_000_000); // Convert to milliseconds

            // Build CSV line
            localCsvBuilder.append(currentPacket).append(',')
                         .append(totalTime.get()).append(',')
                         .append(IPv4.fromIPv4Address(ipv4Packet.getSourceAddress())).append(',')
                         .append(IPv4.fromIPv4Address(ipv4Packet.getDestinationAddress())).append(',')
                         .append(protocol).append(',')
                         .append(ipv4Packet.getTotalLength()).append(',')
                         .append(localInfoBuilder)
                         .append('\n');

            // Distribute to queues using round-robin
            int queueIndex = (currentPacket - 1) % NUM_FILES;
            try {
                if (!packetQueues[queueIndex].offer(localCsvBuilder.toString(), 50, TimeUnit.MICROSECONDS)) {
                    log.warn("Queue {} is full, dropping packet {}", queueIndex, currentPacket);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Interrupted while offering to queue", e);
            }
        }

        private String processPacketInfo(IPv4 ipv4Packet, StringBuilder infoBuilder) {
            String protocol;
            if (ipv4Packet.getPayload() instanceof ICMP) {
                protocol = "ICMP";
                ICMP icmpPkt = (ICMP) ipv4Packet.getPayload();
                infoBuilder.append("Type:").append(icmpPkt.getIcmpType())
                          .append(",Code:").append(icmpPkt.getIcmpCode());
            } else if (ipv4Packet.getPayload() instanceof TCP) {
                protocol = "TCP";
                TCP tcpPkt = (TCP) ipv4Packet.getPayload();
                infoBuilder.append("SrcPort:").append(tcpPkt.getSourcePort())
                          .append(",DstPort:").append(tcpPkt.getDestinationPort());
            } else if (ipv4Packet.getPayload() instanceof UDP) {
                protocol = "UDP";
                UDP udpPkt = (UDP) ipv4Packet.getPayload();
                infoBuilder.append("SrcPort:").append(udpPkt.getSourcePort())
                          .append(",DstPort:").append(udpPkt.getDestinationPort());
            } else {
                protocol = "Unknown";
            }
            return protocol;
        }
    }

    private void flushQueueToFile(int fileIndex) {
        if (packetQueues[fileIndex].isEmpty()) {
            return;
        }

        ByteBuffer buffer = directBuffers[fileIndex];
        buffer.clear();
        
        try (FileChannel channel = FileChannel.open(filePaths[fileIndex], 
                StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            
            int count = 0;
            String packet;
            while (count < BATCH_SIZE && (packet = packetQueues[fileIndex].poll()) != null) {
                byte[] bytes = packet.getBytes();
                if (buffer.remaining() < bytes.length) {
                    // Buffer is full, flush it
                    buffer.flip();
                    channel.write(buffer);
                    buffer.clear();
                }
                buffer.put(bytes);
                count++;
            }
            
            // Final flush
            if (buffer.position() > 0) {
                buffer.flip();
                channel.write(buffer);
            }
        } catch (IOException e) {
            log.error("Error writing to file {}: {}", fileIndex, e.getMessage());
        }
    }

    private void mergeFiles() {
        try {
            // Ensure all queues are flushed before merging
            for (int i = 0; i < NUM_FILES; i++) {
                flushQueueToFile(i);
            }

            // Sử dụng một tên file cố định cho file merged
            String mergedFileName = String.format("%s/merged_traffic.csv", MERGED_FILE_PATH);
            Path mergedPath = Paths.get(mergedFileName);

            // Tạo mới file merged (truncate nếu đã tồn tại)
            try (FileChannel mergedChannel = FileChannel.open(mergedPath,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                
                // Ghi header
                ByteBuffer headerBuffer = ByteBuffer.wrap(
                    "No.,Time,Source,Destination,Protocol,Length,Info\n".getBytes());
                mergedChannel.write(headerBuffer);

                // Merge data từ các file traffic
                ByteBuffer buffer = ByteBuffer.allocateDirect(BUFFER_SIZE);
                for (int i = 0; i < NUM_FILES; i++) {
                    try (FileChannel sourceChannel = FileChannel.open(filePaths[i], StandardOpenOption.READ)) {
                        // Skip header
                        sourceChannel.position(sourceChannel.position() + "No.,Time,Source,Destination,Protocol,Length,Info\n".length());
                        
                        while (sourceChannel.read(buffer) != -1) {
                            buffer.flip();
                            while (buffer.hasRemaining()) {
                                mergedChannel.write(buffer);
                            }
                            buffer.clear();
                        }
                    }
                }
            }

            // Reset các file traffic gốc
            for (int i = 0; i < NUM_FILES; i++) {
                initializeFile(filePaths[i]);
            }

            log.info("Files merged successfully to: {}", mergedFileName);
        } catch (IOException e) {
            log.error("Error merging files: {}", e.getMessage());
        }
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        
        // Final merge before shutdown
        mergeFiles();
        
        // Shutdown thread pools
        writeExecutor.shutdown();
        scheduledExecutor.shutdown();
        try {
            writeExecutor.awaitTermination(5, TimeUnit.SECONDS);
            scheduledExecutor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted during shutdown", e);
        }
        
        log.info("Stopped DDoS Detector");
    }
}
