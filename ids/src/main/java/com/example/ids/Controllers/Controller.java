package com.example.ids.Controllers;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.format.annotation.DateTimeFormat;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.MediaType;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//import org.springframework.web.bind.annotation.RestController;
//import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;
//
//@RestController
public class Controller {
//
//	@GetMapping("/eventinfo")
//	public ResponseData eventInfo() throws Exception {
//		
//		List<String> info = fetchEventInfoService.fetchEventInfo();
//		
//		return new ResponseData(info);
//	}
//	
//	//not needed
//	@PostMapping("/packetclassification")
//	public ResponseData packetClassification() throws Exception {
//		
//		String classification = fetchPacketClassificationService.fetchPacketClassification();
//		
//		return new ResponseDate(classification);
//	}
//	
//	@PostMapping("/alerts")
//	public ResponseData alerts() throws Exception {
//		
//		String alerts = fetchAlertsService.fetchAlerts();
//		
//		return new ResponseData(alerts);
//	}
//	
//	@GetMapping("/report")
//	public ResponseEntity<StreamingResponseBody> report(@RequestParam(name = "startdate", required = true)
//    													@DateTimeFormat(pattern = "dd-MMM-yy") Date startdate),
//														@RequestParam(name = "enddate", required = true)
//														@DateTimeFormat(pattern = "dd-MMM-yy") Date enddate)) 
//			throws Exception {
//				StreamingResponseBody detailReport = outputstream -> {
//					fetchReportService.fetchReport(startdate, outputstream);
//				};
//				return ResponseEntity.ok()
//						.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + fileName(startdate))
//						.contentType(MediaType.valueOf("application/csv"))
//						.body(detailReport);
//	}
//			
//	@PostMapping("/barchart")
//	public ResponseData barChartStats() throws Exception {
//		
//		Integer arr[] = fetchBarChartStatsService.fetchBarChartStats();
//		
//		return new ResponseData(arr);
//	}
//	
//	@PostMapping("/piechart")
//	public ResponseData pieChartStats() throws Exception {
//		
//		Integer arr[] = fetchPieChartStatsService.fetchPieChartStats();
//		
//		return new ResponseData(arr);
//	}
}
