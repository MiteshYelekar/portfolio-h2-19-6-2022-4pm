package com.cognizant.portfolio_management.DailySharePrice;

 

import static org.junit.Assert.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

 

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.cognizant.portfolio_management.DailySharePrice.controller.ShareDetailsController;

 

@AutoConfigureMockMvc
@SpringBootTest
class DailySharePriceApplicationTests {

 

    @Autowired
    private ShareDetailsController shareDetailsController;

 

    @Autowired
    private MockMvc mvc;
    
    @Test
    void contextLoads() {
        assertNotNull(shareDetailsController);
    }
    
    @Test
    public void testGetDailySharePrice() throws Exception {
        ResultActions actions = mvc.perform(get("/dailyshareprice/name/Amazon"));
       
       // actions.andExpect(MockMvcResultMatchers.jsonPath("$[0].shareId").exists());
        //actions.andExpect(jsonPath("$[0].shareId").value("AMZ"));
        
        //actions.andExpect(jsonPath("$.shareName").exists());
        //actions.andExpect(jsonPath("$.shareName").value("Amazon"));
        
       // actions.andExpect(jsonPath("$.shareValue").exists());
        //actions.andExpect(jsonPath("$.shareValue").value("2500.0"));
    }

 

    @Test
    public void testGetAllDailySharePrice() throws Exception {
        ResultActions actions = mvc.perform(get("/dailyallshareprice"));
        
        
    }
    
    
    @Test
    public void testGetDailySharePriceByIDList() throws Exception {
        ResultActions actions = mvc.perform(get("/dailyshareprice/AMZ"));
        
    }
    
    
}
 