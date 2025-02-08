package org.onosproject.ddosdetection;

import org.junit.Before;
import org.junit.Test;
import org.onosproject.core.CoreService;
import org.onosproject.net.packet.PacketService;
import static org.mockito.Mockito.*;

public class AppComponentTest {
    private AppComponent component;
    private CoreService coreService;
    private PacketService packetService;

    @Before
    public void setUp() {
        // Khởi tạo component và mock các dependency
        component = new AppComponent();
        
        // Tạo mock cho các service
        coreService = mock(CoreService.class);
        packetService = mock(PacketService.class);
        
        // Inject mock services
        component.coreService = coreService;
        component.packetService = packetService;
    }

    @Test
    public void testActivate() {
        // Thực hiện test activate method
        component.activate();
        
        // Verify các phương thức được gọi
        verify(coreService).registerApplication(anyString());
        verify(packetService).addProcessor(any(), anyInt());
    }

    @Test
    public void testDeactivate() {
        // Thực hiện test deactivate method
        component.activate(); // Đảm bảo đã activate trước
        component.deactivate();
        
        // Verify processor được remove
        verify(packetService).removeProcessor(any());
    }
}
