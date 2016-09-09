///////////////////////////////////////////////////////////////////////
// OpenCV tracking example.
// Written by darkpgmr (http://darkpgmr.tistory.com), 2013

//#include "stdafx.h"
//#include <windows.h>
#include <iostream>
#include <math.h>
#include "tracker_opencv.h"

vector<Point2f> obj_corners(4);

using namespace std;

tracker_opencv::tracker_opencv(void)
{
}

tracker_opencv::~tracker_opencv(void)
{
}

Mat tracker_opencv::setRoiObjectMaskOnBackScreen(Mat* roiMat)
{
    int largest_area=0;
    int largest_contour_index=0;
    Rect bounding_rect;
    
    Mat thr(roiMat->rows,roiMat->cols,CV_8UC1);
    Mat dst(roiMat->rows,roiMat->cols,CV_8UC1,Scalar::all(0));
    cvtColor(*roiMat,thr,CV_BGR2GRAY); //Convert to gray
    threshold(thr, thr,100, 255,THRESH_BINARY); //Threshold the gray 25 -> 100
    
    vector<vector<Point>> contours; // Vector for storing contour
    vector<Vec4i> hierarchy;
    
    //findContours( thr, contours, hierarchy,CV_RETR_CCOMP, CV_CHAIN_APPROX_SIMPLE ); // Find the contours in the image
    findContours( thr, contours, hierarchy,CV_RETR_CCOMP, CV_CHAIN_APPROX_SIMPLE ); // Find the contours in the image

    
    for( int i = 0; i< contours.size(); i++ ) // iterate through each contour.
    {
        double a=contourArea( contours[i],false);  //  Find the area of contour
        if(a>largest_area){
            largest_area=a;
            largest_contour_index=i;                //Store the index of largest contour
            bounding_rect=boundingRect(contours[i]); // Find the bounding rectangle for biggest contour
        }
        
        Scalar color( 255,255,255);
        drawContours( dst, contours, i, color, CV_FILLED, 8, hierarchy );
    }
    
    Scalar color( 0,0,0);
    drawContours( dst, contours,largest_contour_index, color, CV_FILLED, 8, hierarchy ); // Draw the largest contour using previously stored index.
    //rectangle(*roiMat, bounding_rect,  Scalar(0,255,0),1, 8,0);
    rectangle(dst, bounding_rect,  Scalar(0,0,0),1, 8,0);
    
    imshow( "dst", dst );
    //imshow( "view contour", *roiMat );
    
    return dst;
}

void tracker_opencv::init(Mat img, Rect rc)
{
    m_rc = rc;
    m_prevRc = rc;
    vDesObject.clear();
    points[0].clear();
    points[1].clear();
    points[2].clear();
    ori_points.clear();
    
	Mat mask = Mat::zeros(m_rc.height, m_rc.width, CV_8U);
	
    //gclee add
    ellipse(mask, Point(m_rc.width/2, m_rc.height/2), Size(m_rc.width/2, m_rc.height/2), 0, 0, 360, 255, CV_FILLED);
    //rectangle(mask, rc, Scalar(255,255,255), 1, CV_AA); //3, CV_FILLED
    roi_width = m_rc.width;
    roi_height = m_rc.height;
    //gclee add end
    
    //gclee add
    cv::Size s = img.size();
    
    //gclee nead modify
    
    Mat featureMask = Mat::zeros(s.height, s.width, CV_8UC1);
    
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //featureMask(m_rc).setTo(Scalar(255));
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    Mat roiMat = img(m_rc);
    Mat roiMask = setRoiObjectMaskOnBackScreen(&roiMat);
    roiMask.copyTo(featureMask(m_rc));
    
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//    Mat featureMask2 = Mat::zeros(s.height, s.width, CV_8UC1);
   
//    Mat roiMat = img(rc);
//    Mat roiGray;
//    cvtColor(roiMat, roiGray, COLOR_BGR2GRAY);
    //cv::threshold(roiGray,roiGray,SENSITIVITY_VALUE,255,THRESH_BINARY);
    //cv::erode(roiGray, roiGray, noArray());
    //cv::dilate(roiGray, roiGray, noArray());
    
  //  roiGray.copyTo(featureMask(rc));
    //rectangle(featureMask, rc, Scalar(255,255,255), 3, CV_FILLED); //3, CV_FILLED
    //roiGray.copyTo(featureMask);
    //ellipse(featureMask, Point(rc.width/2, rc.height/2), Size(rc.width/2, rc.height/2), 0, 0, 360, 255, CV_FILLED);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    cv::imshow("New ROI MASK Image", featureMask);
    
    cvtColor(img, gray, CV_BGR2GRAY);
    // automatic initialization
    goodFeaturesToTrack(gray, points[0], MAX_COUNT, 0.01, 10, featureMask, 3, 0, 0.04); //10 featureMask
    //cornerSubPix(gray, points[0], subPixWinSize, Size(-1,-1), termcrit);
    ori_points = points[0];
    //gclee add end
    
	if(img.channels()<=1)
	{
		float vrange[] = {0,256};
		const float* phranges = vrange;
		Mat roi(img, rc);
		calcHist(&roi, 1, 0, mask, m_model, 1, &m_param.hist_bins, &phranges);
	}
	else if(m_param.color_model==CM_GRAY)
	{
//		Mat gray;
//		cvtColor(img, gray, CV_BGR2GRAY);
//
//		float vrange[] = {0,256};
//		const float* phranges = vrange;
//		Mat roi(gray, rc);
//		calcHist(&roi, 1, 0, mask, m_model, 1, &m_param.hist_bins, &phranges);
        
        //gclee add
//        cv::Size s = img.size();
//        Mat featureMask = Mat::zeros(s.height, s.width, CV_8UC1);
//        rectangle(featureMask, rc, Scalar(255,255,255), 3, CV_FILLED);
//        
//        cvtColor(img, gray, CV_BGR2GRAY);
//        // automatic initialization
//        goodFeaturesToTrack(gray, points[0], MAX_COUNT, 0.01, 1, featureMask, 3, 0, 0.04); //10
//        cornerSubPix(gray, points[0], subPixWinSize, Size(-1,-1), termcrit);
        //gclee add end
        
        //gclee add keypoint -----------------------------------------------------------------------------------------------------------
        
        // Convert each roi to grayscale
        object = img(m_rc).clone();      // Crop is color CV_8UC3
        cvtColor(object, object, COLOR_BGR2GRAY); // Now crop is grayscale CV_8UC1
        //cv::threshold(object,object,SENSITIVITY_VALUE,255,THRESH_BINARY);
        //gclee nead modity
        cv::imshow("ROI Image", object);
        
        if (!object.data){
            cout<<"Can't create ROI gray image\n";
            return;
        }
        
        //SURF Detector, and descriptor parameters
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        int minH;
        
        minH=100;
        SurfFeatureDetector detector(minH);
        detector.detect(object, kpObject);
        SurfDescriptorExtractor extractor;
        extractor.compute(object, kpObject, desObject);
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        vDesObject.push_back(desObject);
        
        obj_corners[0] = cvPoint(0,0);
        obj_corners[1] = cvPoint( object.cols, 0 );
        obj_corners[2] = cvPoint( object.cols, object.rows );
        obj_corners[3] = cvPoint( 0, object.rows );
        
        //gclee debug
//        for(unsigned int i = 0; i < kpObject.size(); i++ )
//        {
//            circle( img, kpObject[i].pt, 3, Scalar(255,0,0), -1, 8);
//        }
//
//        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//        //# meanshift add (HSV)
//        Mat hsv;
//        cvtColor(img, hsv, CV_BGR2HSV);
//        
//        float hrange[] = {0,180};
//        float vrange[] = {0,255};
//        const float* ranges[] = {hrange, vrange, vrange};	// hue, saturation, brightness
//        int channels[] = {0, 1, 2};
//        int hist_sizes[] = {m_param.hist_bins, m_param.hist_bins, m_param.hist_bins};
//        Mat roi(hsv, m_rc);
//        calcHist(&roi, 1, channels, mask, m_model3d, 3, hist_sizes, ranges);
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        //gclee add keypoint end -----------------------------------------------------------------------------------------------------------
        
	}
	else if(m_param.color_model==CM_HUE)
	{
		Mat hsv;
		cvtColor(img, hsv, CV_BGR2HSV);

		float hrange[] = {0,180};
		const float* phranges = hrange;
		int channels[] = {0};
		Mat roi(hsv, rc);
		calcHist(&roi, 1, channels, mask, m_model, 1, &m_param.hist_bins, &phranges);
	}
	else if(m_param.color_model==CM_RGB)
	{
		float vrange[] = {0,255};
		const float* ranges[] = {vrange, vrange, vrange};	// B,G,R
		int channels[] = {0, 1, 2};
		int hist_sizes[] = {m_param.hist_bins, m_param.hist_bins, m_param.hist_bins};
		Mat roi(img, rc);
		calcHist(&roi, 1, channels, mask, m_model3d, 3, hist_sizes, ranges);
	}
	else if(m_param.color_model==CM_HSV)
	{
		Mat hsv;
		cvtColor(img, hsv, CV_BGR2HSV);

		float hrange[] = {0,180};
		float vrange[] = {0,255};
		const float* ranges[] = {hrange, vrange, vrange};	// hue, saturation, brightness
		int channels[] = {0, 1, 2};
		int hist_sizes[] = {m_param.hist_bins, m_param.hist_bins, m_param.hist_bins};
		Mat roi(hsv, rc);
		calcHist(&roi, 1, channels, mask, m_model3d, 3, hist_sizes, ranges);
	}

	m_rc = rc;
}

bool tracker_opencv::run(Mat img, Rect& rc)
{
    int reInit = 0;
    // histogram backprojection
    if(img.channels()<=1)
    {
        float vrange[] = {0,256};
		const float* phranges = vrange;
		calcBackProject(&img, 1, 0, m_model, m_backproj, &phranges);
	}
	else if(m_param.color_model==CM_GRAY)
	{
		cvtColor(img, gray, CV_BGR2GRAY);
        
        ///////////////////////////////////////////////////////////////////
//
//		float vrange[] = {0,256};
//		const float* phranges = vrange;
//		calcBackProject(&gray, 1, 0, m_model, m_backproj, &phranges);
        
        //gclee add
//        xmin = ymax = xmax = ymin = 0;
//        cvtColor(img, gray, CV_BGR2GRAY);
//
        // first : meanshif =================================================================================================
//        float hrange[] = {0,180};
//        float vrange[] = {0,255};
//        const float* ranges[] = {hrange, vrange, vrange};	// hue, saturation, brightness
//        int channels[] = {0, 1, 2};
////        int hist_sizes[] = {m_param.hist_bins, m_param.hist_bins, m_param.hist_bins};
////
////        Mat roi(img, m_rc);
////        Mat tempMask = Mat::zeros(m_rc.height, m_rc.width, CV_8U);
////        ellipse(tempMask, Point(m_rc.width/2, m_rc.height/2), Size(m_rc.width/2, m_rc.height/2), 0, 0, 360, 255, CV_FILLED);
////        //rectangle(tempMask, m_rc, Scalar(255,255,255), 3, CV_FILLED);
////        calcHist(&roi, 1, channels, tempMask, m_model3d, 3, hist_sizes, ranges);
//        
//        Mat hsv;
//        cvtColor(img, hsv, CV_BGR2HSV);
//        calcBackProject(&hsv, 1, channels, m_model3d, m_backproj, ranges);
//        
//        int itrs = meanShift(m_backproj, m_rc, TermCriteria( CV_TERMCRIT_EPS | CV_TERMCRIT_ITER, m_param.max_itrs, 1 ));
//        cout << "xval:" << m_rc.x << " yval:" << m_rc.y << " width:" << m_rc.width << " height:" << m_rc.height << "\n";
//        rectangle(img, m_rc, Scalar(0,0,255), 2, CV_AA);
        
        // first end =================================================================================================
        
        if( !points[0].empty() ){
            if(prevGray.empty())
                gray.copyTo(prevGray);
            
            calcOpticalFlowPyrLK(prevGray, gray, points[0], points[1], status, err, winSize,
                                 3, termcrit, 0, 0.001);
            
            //cornerSubPix(gray, points[1], subPixWinSize, Size(-1,-1), termcrit);
            
            xmax = ymax = 0;
            xmin = ymin = 10000;
            
            cout << "points size:" << points[1].size() << "\n";
            
            
            xroicenter = m_rc.x + m_rc.width/2;
            yroicenter = m_rc.y + m_rc.height/2;
            
            points[2].clear();
            
            if(points[1].size() < 2 )
                return true;
            
//            if(points[1].size() < 1)
//                points[0] = ori_points;
            /////////////////////////////////////////////////////////////////////////////////////
            int flowX = 0; // -1 right, 1 left
            int flowY = 0; // -1 down, 1 up
            int flowXleftCount = 0, flowXrightCount = 0;
            int flowYdownCount = 0, flowYupCount = 0;
            double total_distance_x = 0, total_distance_y = 0;
            double ori_distance_x = 0, ori_distance_y = 0;
            int check_fail_points = 0; // 1 : check
            int nTotal = 0;
            double d_temp_x = 0, d_temp_y;
            for( int n = 0; n < points[1].size(); n++ ){
                
                if( !status[n] ){
                    cout << "after status error)\n";
                    continue;
                }
                
                nTotal++;
 
                //distance before frame
                total_distance_x += abs(points[0].at(n).x - points[1].at(n).x);
                //distance ori frame
                ori_distance_x += abs(ori_points.at(n).x - points[1].at(n).x);
                
                d_temp_x = points[0].at(n).x - points[1].at(n).x;
                if(abs(d_temp_x) > 1.1 && d_temp_x < 0){
                    //flow right
                    flowXrightCount++;
                }else if(abs(d_temp_x) > 1.1 && d_temp_x > 0 ){
                    flowXleftCount++;
                }
                
                total_distance_y += abs(points[0].at(n).y - points[1].at(n).y);
                ori_distance_y += abs(ori_points.at(n).y - points[1].at(n).y);
                d_temp_y = points[0].at(n).y - points[1].at(n).y;
                if(abs(d_temp_y) > 1.1 && d_temp_y < 0){
                    //flow down
                    flowYdownCount++;
                }else if(abs(d_temp_y) > 1.1 && d_temp_y > 0 ){
                    flowYupCount++;
                }
            }
            
            total_distance_x = total_distance_x / nTotal;
            total_distance_y = total_distance_y / nTotal;
            ori_distance_x = ori_distance_x / nTotal;
            ori_distance_y = ori_distance_y / nTotal;
            
            cout << "total distance x: " << total_distance_x << " y: " << total_distance_y << "\n";
            if( total_distance_x > 1.1 || total_distance_y > 1.1){
                cout << "let's go check fail points ********************\n";
                check_fail_points = 1;
            }
            
            // 일부 points만 움직임, object를 앞에서 가림, 10%미만인 경우 에러로 확인함
            d_temp_x = flowXrightCount+flowXleftCount;
            d_temp_y = flowYupCount+flowYdownCount;
            if( d_temp_x/(points[1].size())?points[1].size():1 * 100 < 10 ||
               d_temp_y/(points[1].size())?points[1].size():1 * 100 < 10){
                
//                m_rc.width = 0;m_rc.height = 0;
//                std::swap(points[2], points[0]);
//                std::swap(ori_points_temp, ori_points);
//                gray.copyTo(prevGray);
                
                points[2].clear();
                ori_points_temp.clear();
                points[0].clear();
                points[1].clear();
                points[2].clear();
                ori_points.clear();
                cout << "hide object so return ******************** move count: " << d_temp_x << ":" << d_temp_y << ":" << points[1].size() << " \n";
                return true;
            }
            
            /////////////////////////////////////////////////////////////////////////////////////
            (flowXrightCount > flowXleftCount)?flowX = -1:flowX = 1;
            (flowYdownCount > flowYupCount)?flowY = -1:flowY = 1;
            /////////////////////////////////////////////////////////////////////////////////////
            
            ori_points_temp.clear();
            for( i = k = 0; i < points[1].size(); i++ )
            {
                if( !status[i] ){
                    cout << "status error)\n";
                    continue;
                }
                
                if( check_fail_points ){
                    
                    d_temp_x = abs(points[0].at(i).x - points[1].at(i).x);
                    d_temp_y = abs(points[0].at(i).y - points[1].at(i).y);
                    
                    if( d_temp_x < 0.1 && d_temp_y < 0.1){
                        continue;
                    }
                    
                    
                    // to right & up
//                    if(flowX == -1 && flowY == 1){
//                        if(ori_points.at(i).x - points[1].at(i).x > 0 && ori_points.at(i).y - points[1].at(i).y < 0){
//                            continue;
//                        }
//                    }
//                    
//                    // to right & down
//                    if(flowX == -1 && flowY == -1){
//                        if(ori_points.at(i).x - points[1].at(i).x > 0 && ori_points.at(i).y - points[1].at(i).y > 0){
//                            continue;
//                        }
//                    }
//                    
//                    // to left & up
//                    if(flowX == 1 && flowY == 1){
//                        if(ori_points.at(i).x - points[1].at(i).x < 0 && ori_points.at(i).y - points[1].at(i).y < 0){
//                            continue;
//                        }
//                    }
//                    
//                    // to left & down
//                    if(flowX == 1 && flowY == -1){
//                        if(ori_points.at(i).x - points[1].at(i).x < 0 && ori_points.at(i).y - points[1].at(i).y > 0){
//                            continue;
//                        }
//                    }
                    
//                    if(flowX == -1){ // to right
//                        if(ori_points.at(i).x - points[1].at(i).x > 0){
//                            continue;
//                        }
//                    }else{           // to left
//                        if(ori_points.at(i).x - points[1].at(i).x < 0){
//                            continue;
//                        }
//                    }
//                    
//                    if(flowY == -1){ // to down
//                        if(ori_points.at(i).y - points[1].at(i).y > 0){
//                            continue;
//                        }
//                    }else{           // to up
//                        if(ori_points.at(i).y - points[1].at(i).y < 0){
//                            continue;
//                        }
//                    }
                    
//                    d_temp = abs(abs((ori_points.at(i).x - points[1].at(i).x)) - ori_distance_x);
//                    cout << "avg diff width: " << d_temp << "\n";
//                    if( d_temp > 10){
//                        continue;
//                    }
//                    
//                    d_temp = abs(abs((ori_points.at(i).y - points[1].at(i).y)) - ori_distance_y);
//                    cout << "avg diff height: " << d_temp << "\n";
//                    if( d_temp > 10){
//                        continue;
//                    }
                    
                }
                 //cout << "abs x : " << abs(points[0].at(i).x - points[1].at(i).x) << "\n";
                
//                if( abs(points[0].at(i).x - points[1].at(i).x) < 0.001  ){
//                    continue;
//                }
//                
//                if( abs(points[0].at(i).y - points[1].at(i).y) < 0.001 ){
//                    continue;
//                }
                
//                if( err[i] < 1){
//                    cout << "err value" << err[i] << "\n";
//                    //continue;
//                }
                
                //////////////////////////////////////////////////////////////////////////////////////////////
//                if(i != 0){
//                    int nDistance = points[1].at(i-1).x - points[1].at(i).x;
//                    if(nDistance > 20)
//                        continue;
//                    
//                    nDistance = points[1].at(i-1).y - points[1].at(i).y;
//                    if(nDistance > 20)
//                        continue;
//                }
                //////////////////////////////////////////////////////////////////////////////////////////////
//                //////////////////////////////////////////////////////////////////////////////////////////////
//                if(points[0].at(i).x == points[1].at(i).x && points[0].at(i).y == points[1].at(i).y)
//                    continue;
//                //////////////////////////////////////////////////////////////////////////////////////////////
//                
                txval = points[1].at(i).x;
                tyval = points[1].at(i).y;
                
                //cout << "txval:" << txval << " tyval:" << tyval << "\n";
                //cout << "xroicenter:" << xroicenter << " yroicenter:" << yroicenter << "\n";

//                if( abs(txval - xroicenter) > 40 ){
//                    //reInit = 1;
//                    cout << "abs x value" << abs(txval - xroicenter) << "\n";
//                    //continue;
//                }
//                if( abs(tyval - yroicenter) > 40 ){
//                    //reInit = 1;
//                    cout << "abs y value" << abs(tyval - yroicenter) << "\n";
//                    //continue;
//                }
                
                if(xmin > txval)
                    xmin = txval;
                if(ymax < tyval)
                    ymax = tyval;
                if(xmax < txval)
                    xmax = txval;
                if(ymin > tyval)
                    ymin = tyval;
                
                circle( img, points[1][i], 3, Scalar(0,255,0), -1, 8);
                circle( img, points[0][i], 3, Scalar(0,0,255), -1, 8);
                
                line(img, ori_points.at(i), points[1][i], Scalar(255,255,255));
                
                points[2].push_back(points[1][i]);
                ori_points_temp.push_back(ori_points[i]);
                
            }
            
            if(xmin == 10000 || ymin == 1000 || xmax == 0 || ymax == 0){
                //fail
                reInit = 0;
                return true;
            }
            
            Rect tRect(xmin, ymin, xmax-xmin, ymax-ymin);
            //tracking
            //decision find object true or false (for width & height)
            //float cRatio = (ymax-ymin)/(xmax-xmin);
            
            (m_prevRc.width == 0)?m_prevRc.width = 10:m_prevRc.width = m_prevRc.width;
            (m_prevRc.height == 0)?m_prevRc.height = 10:m_prevRc.height = m_prevRc.height;
            
            //float pRatio = (m_prevRc.height)/(m_prevRc.width);
            //if(abs(pRatio - cRatio) > 2){
            //if( !(cRatio > 0.5 && cRatio < 2) ){
            if( false ){
                //cout << "fail find object so change keypoint Ratio diff value : " << abs(pRatio - cRatio) << "======================> \n";
                //find object fail for goodFeature
                //find key point
                if(findObjectKeyPoint(img))
                    rectangle(img, m_rc, Scalar(0,255,0), 3, 4);
                
            }else{
                m_rc = tRect;
                xroicenter = m_rc.x + m_rc.width/2;
                yroicenter = m_rc.y + m_rc.height/2;
                
                (m_rc.width == 0)?m_rc.width = 10:m_rc.width = m_rc.width;
                (m_rc.height == 0)?m_rc.height = 10:m_rc.height = m_rc.height;

                rectangle(img, m_rc, Scalar(0,255,0), 3, 4);
                // save key points //////////////////////////////////////////////////////////////////////////////
//                object = img(m_rc).clone();      // Crop is color CV_8UC3
//                cvtColor(object, object, COLOR_BGR2GRAY); // Now crop is grayscale CV_8UC1
//                cv::imshow("NEW key_point ROI Image", object);
//                detector = SurfFeatureDetector(minHess);
//                detector.detect(object, kpObject);
//                SurfDescriptorExtractor extractor;
//                extractor.compute(object, kpObject, desObject);
//                
//                // insert new keyPoints's desObect
//                if(vDesObject.size() < 1){
//                    vDesObject.push_back(desObject);
//                }else{
////                    int isEqual = 0;
////                    for(unsigned int i = 0; i < vDesObject.size(); i++ )
////                    {
////                        if(isEqualKeyPoint(desObject, vDesObject[i])){
////                            cout << " there is eaual keypoints so pass save ======================> \n";
////                            isEqual = 1;
////                        }
////                    }
////                    
////                    if(!isEqual){
//                        if(vDesObject.size() == 100){
//                            cout << "vDesObject size > 100 last offset update ======================> \n";
//                            vDesObject[vDesObject.size()-1] = desObject;
//                        }else{
//                            cout << "vDesObject size < 100 add ======================> \n";
//                            vDesObject.push_back(desObject);
//                            
//                        }
////                    }
//                }
                // save key points end //////////////////////////////////////////////////////////////////////////
                
            }
            
            //re ini ////////////////////////////////////////////////////////////////////////////////////////////////////
            if(reInit){
                reInit = 0;
                cv::Size s = img.size();
                Mat featureMask = Mat::zeros(s.height, s.width, CV_8UC1);
                featureMask(m_rc).setTo(Scalar(255));
                rectangle(featureMask, m_rc, Scalar(255,255,255), 3, CV_FILLED); //3, CV_FILLED
                //ellipse(featureMask, Point(rc.width/2, rc.height/2), Size(rc.width/2, rc.height/2), 0, 0, 360, 255, CV_FILLED);
                // automatic initialization
                goodFeaturesToTrack(gray, points[0], MAX_COUNT, 0.01, 10, featureMask, 3, 0, 0.04); //10 featureMask
                cornerSubPix(gray, points[0], subPixWinSize, Size(-1,-1), termcrit);
                //gclee add end
            }
            //re ini end /////////////////////////////////////////////////////////////////////////////////////////////////
            
            cout << "end draw rect ======================> \n";
            
            std::swap(points[2], points[0]);
            std::swap(ori_points_temp, ori_points);
            gray.copyTo(prevGray);
            
            points[2].clear();
            ori_points_temp.clear();
            
        }
        
        rc = m_rc;
        m_prevRc = m_rc;
        return true;
        
//        gclee add end
        
        //gclee add keypoint
//        cvtColor(img, gray, CV_BGR2GRAY);
//        
//        Mat des_image, H;
//        
//        vector<KeyPoint> kp_image;
//        vector<vector<DMatch > > matches;
//        vector<DMatch > good_matches;
//        vector<Point2f> obj;
//        vector<Point2f> scene;
//        vector<Point2f> scene_corners(4);
//        
//        detector.detect( gray, kp_image );
//        extractor.compute( gray, kp_image, des_image );
//        matcher.knnMatch(desObject, des_image, matches, 2);
//        
//        for(int i = 0; i < min(des_image.rows-1,(int) matches.size()); i++) //THIS LOOP IS SENSITIVE TO SEGFAULTS
//        {
//            if((matches[i][0].distance < thresholdMatchingNN*(matches[i][1].distance)) && ((int) matches[i].size()<=2 && (int) matches[i].size()>0))
//            {
//                good_matches.push_back(matches[i][0]);
//            }
//        }
//        
//        if (good_matches.size() >= thresholdGoodMatches)
//        {
//            
//            //Display that the object is found
//            putText(img, "Object Found", cvPoint(10,50),FONT_HERSHEY_COMPLEX_SMALL, 2, cvScalar(0,0,250), 1, CV_AA);
//            int xTotalVal =0, yTotalVal =0;
//            for(unsigned int i = 0; i < good_matches.size(); i++ )
//            {
//                //Get the keypoints from the good matches
//                obj.push_back( kpObject[ good_matches[i].queryIdx ].pt );
//                scene.push_back( kp_image[ good_matches[i].trainIdx ].pt );
//                
//                circle( img, kp_image[ good_matches[i].trainIdx ].pt, 3, Scalar(0,255,0), -1, CV_AA);
//                
//                xTotalVal += kp_image[ good_matches[i].trainIdx ].pt.x;
//                yTotalVal += kp_image[ good_matches[i].trainIdx ].pt.y;
//                //circle( img, kpObject[ good_matches[i].queryIdx ].pt, 3, Scalar(0,255,255), -1, 8);
//            }
//            
//            H = findHomography( obj, scene, CV_RANSAC );
//            perspectiveTransform( obj_corners, scene_corners, H);
//            
//            line(img, scene_corners[0], scene_corners[1], Scalar(0, 255, 0), 4 );
//            line(img, scene_corners[1], scene_corners[2], Scalar(0, 255, 0), 4 );
//            line(img, scene_corners[2], scene_corners[3], Scalar(0, 255, 0), 4 );
//            line(img, scene_corners[3], scene_corners[0], Scalar(0, 255, 0), 4 );
//            
//            //circle( img, kpObject[ good_matches[i].queryIdx ].pt, 3, Scalar(0,255,255), -1, 8);
//            
//            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//            xTotalVal = xTotalVal/good_matches.size();
//            yTotalVal = yTotalVal/good_matches.size();
//            
//            
//            Rect newRoiRect(xTotalVal-newRoiSize/2, yTotalVal-newRoiSize/2, newRoiSize, newRoiSize);
//            cv::Size s = img.size();
//            if(newRoiRect.x + newRoiRect.width >= s.width || newRoiRect.y + newRoiRect.height >= s.height || newRoiRect.x <= 0 || newRoiRect.y <= 0)
//            {
//                cout<<"Can't create NEW ROI \n";
//                return true;
//            }
//            m_rc = newRoiRect;
//            
//            //# meanshift add (HSV)
//            float hrange[] = {0,180};
//            float vrange[] = {0,255};
//            const float* ranges[] = {hrange, vrange, vrange};	// hue, saturation, brightness
//            int channels[] = {0, 1, 2};
//            int hist_sizes[] = {m_param.hist_bins, m_param.hist_bins, m_param.hist_bins};
//            
//            Mat roi(img, m_rc);
//            Mat tempMask = Mat::zeros(m_rc.height, m_rc.width, CV_8U);
//            rectangle(tempMask, m_rc, Scalar(255,255,255), 3, CV_FILLED);
//            calcHist(&roi, 1, channels, tempMask, m_model3d, 3, hist_sizes, ranges);
//            Mat hsv;
//            cvtColor(img, hsv, CV_BGR2HSV);
//            calcBackProject(&hsv, 1, channels, m_model3d, m_backproj, ranges);
//            
////            object = img(m_rc).clone();      // Crop is color CV_8UC3
////            cvtColor(object, object, COLOR_BGR2GRAY); // Now crop is grayscale CV_8UC1
//            cv::imshow("New ROI Image", roi);
//
//            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//           
//        }else{
//            
//            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//            // # add meanshift (HSV)
//            int itrs = meanShift(m_backproj, m_rc, TermCriteria( CV_TERMCRIT_EPS | CV_TERMCRIT_ITER, m_param.max_itrs, 1 ));
//            //cout << "xval:" << m_rc.x << " yval:" << m_rc.y << " width:" << m_rc.width << " height:" << m_rc.height << "\n";
//            rectangle(img, m_rc, Scalar(0,0,255), 2, CV_AA);
//            
//            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//            //# meanshift add (HSV)
//            float hrange[] = {0,180};
//            float vrange[] = {0,255};
//            const float* ranges[] = {hrange, vrange, vrange};	// hue, saturation, brightness
//            int channels[] = {0, 1, 2};
//            int hist_sizes[] = {m_param.hist_bins, m_param.hist_bins, m_param.hist_bins};
//            Mat roi(img, m_rc);
//            Mat tempMask = Mat::zeros(m_rc.height, m_rc.width, CV_8U);
//            rectangle(tempMask, m_rc, Scalar(255,255,255), 3, CV_FILLED);
//            calcHist(&roi, 1, channels, tempMask, m_model3d, 3, hist_sizes, ranges);
//            Mat hsv;
//            cvtColor(img, hsv, CV_BGR2HSV);
//            calcBackProject(&hsv, 1, channels, m_model3d, m_backproj, ranges);
//           
//            //#############################################################
//            object = img(m_rc).clone();      // Crop is color CV_8UC3
//            cvtColor(object, object, COLOR_BGR2GRAY); // Now crop is grayscale CV_8UC1
//            cv::imshow("ROI Image", object);
//            if (!object.data){
//                cout<<"Can't create ROI gray image\n";
//                return true;
//            }
//            detector.detect(object, kpObject);
//            SurfDescriptorExtractor extractor;
//            extractor.compute(object, kpObject, desObject);
//            
//            obj_corners[0] = cvPoint(0,0);
//            obj_corners[1] = cvPoint( object.cols, 0 );
//            obj_corners[2] = cvPoint( object.cols, object.rows );
//            obj_corners[3] = cvPoint( 0, object.rows );
//            
//            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//            
//        }
//        
//        
//        
//        rc = m_rc;
//        
//        return true;

        
        //gclee add keypoint end
        
	}
	else if(m_param.color_model==CM_HUE)
	{
		Mat hsv;
		cvtColor(img, hsv, CV_BGR2HSV);

		float hrange[] = {0,180};
		const float* phranges = hrange;
		int channels[] = {0};
		calcBackProject(&hsv, 1, channels, m_model, m_backproj, &phranges);
	}
	else if(m_param.color_model==CM_RGB)
	{
		float vrange[] = {0,255};
		const float* ranges[] = {vrange, vrange, vrange};	// B,G,R
		int channels[] = {0, 1, 2};
		int hist_sizes[] = {m_param.hist_bins, m_param.hist_bins, m_param.hist_bins};
		calcBackProject(&img, 1, channels, m_model3d, m_backproj, ranges);
	}
	else if(m_param.color_model==CM_HSV)
	{
		Mat hsv;
		cvtColor(img, hsv, CV_BGR2HSV);

		float hrange[] = {0,180};
		float vrange[] = {0,255};
		const float* ranges[] = {hrange, vrange, vrange};	// hue, saturation, brightness
		int channels[] = {0, 1, 2};
		calcBackProject(&hsv, 1, channels, m_model3d, m_backproj, ranges);
	}

    //gclee add
	// tracking
	if(m_param.method == MEANSHIFT)
	{
        
		int itrs = meanShift(m_backproj, m_rc, TermCriteria( CV_TERMCRIT_EPS | CV_TERMCRIT_ITER, m_param.max_itrs, 1 ));
        rectangle(img, m_rc, Scalar(0,0,255), 2, CV_AA);
        //gclee add
//        cv::Size s = img.size();
//        Mat featureMask = Mat::zeros(s.height, s.width, CV_8UC1);
//        rectangle(featureMask, m_rc, Scalar(255,255,255), 3, CV_FILLED);
//        
//        cvtColor(img, gray, CV_BGR2GRAY);
//        // automatic initialization
//        goodFeaturesToTrack(gray, points[1], MAX_COUNT, 0.01, 10, featureMask, 3, 0, 0.04); //10
//        cornerSubPix(gray, points[1], subPixWinSize, Size(-1,-1), termcrit);
     
//        int iDiff = points[0].size() - points[1].size();
//        iDiff = abs(iDiff);
//        
//        if(iDiff > 15){
//            //std::swap(points[1], points[0]);
//            cout << "  points size different ------------>\n";
//            cout << "0 size:" << points[0].size() << " 1 size:" << points[1].size() << "\n";
//            rectangle(img, m_prevRc, Scalar(0,0,255), 2, CV_AA);
//        }else{
//            rectangle(img, m_rc, Scalar(0,0,255), 2, CV_AA);
//            m_prevRc = m_rc;
//        }
           //gclee add end
        
		
	}
	else if(m_param.method == CAMSHIFT)
	{
		if(m_rc.width>0 && m_rc.height>0)
		{
			RotatedRect trackBox = CamShift(m_backproj, m_rc, TermCriteria( CV_TERMCRIT_EPS | CV_TERMCRIT_ITER, m_param.max_itrs, 1));
			ellipse( img, trackBox, Scalar(0,0,255), 3, CV_AA );
		}

		if(m_rc.width<=1 || m_rc.height<=1)
		{
			int cols = m_backproj.cols, rows = m_backproj.rows, r = (MIN(cols, rows) + 5)/6;
			m_rc = Rect(m_rc.x-r, m_rc.y-r, m_rc.width+2*r, m_rc.height+2*r) & Rect(0, 0, cols, rows);
		}
	}
    //gclee add end

	rc = m_rc;
    return true;
}

void tracker_opencv::configure()
{
    /////////////////////////////////////////////////////////////////////////////////////
    // test
    m_param.method = MEANSHIFT;
    m_param.color_model = CM_GRAY;
    /////////////////////////////////////////////////////////////////////////////////////
    
//    char sel = -1;
//    cout << "  1. camshift\n"
//    << "  2. meanshift\n";
//    cout << "select tracking method[1-2]: ";
//    cin >> sel;
//    cout << endl;
//    
//    if(sel=='1')
//        m_param.method = CAMSHIFT;
//    else if(sel=='2')
//        m_param.method = MEANSHIFT;
//    
//    cout << "  1. HSV\n"
//    << "  2. RGB\n"
//    << "  3. hue\n"
//    << "  4. gray\n";
//    cout << "select color model[1-4]: ";
//    cin >> sel;
//    cout << endl;
//    
//    if(sel=='1')
//        m_param.color_model = CM_HSV;
//    else if(sel=='2')
//        m_param.color_model = CM_RGB;
//    else if(sel=='3')
//        m_param.color_model = CM_HUE;
//    else if(sel=='4')
//        m_param.color_model = CM_GRAY;
}

Mat tracker_opencv::get_bp_image()
{
	normalize(m_backproj, m_backproj, 0, 255, CV_MINMAX);
	return m_backproj;
}

bool tracker_opencv::isEqualKeyPoint(Mat target, Mat source)
{
    // bug bug
    vector<vector<DMatch > > matches;
    matcher.knnMatch(target, source, matches, 2);
    vector<DMatch > good_matches;
    
    for(int i = 0; i < min(source.rows-1,(int) matches.size()); i++) //THIS LOOP IS SENSITIVE TO SEGFAULTS
    {
        if((matches[i][0].distance < thresholdMatchingNN*(matches[i][1].distance)) && ((int) matches[i].size()<=2 && (int) matches[i].size()>0))
        {
            good_matches.push_back(matches[i][0]);
        }
    }
    
    if (good_matches.size() >= thresholdGoodMatches)
        return true;
    
    return false;
    
}

bool tracker_opencv::findObjectKeyPoint(Mat img)
{
    
    Mat des_image, H;
    
    vector<KeyPoint> kp_image;
    vector<vector<DMatch > > matches;
    vector<DMatch > good_matches;
    vector<Point2f> obj;
    vector<Point2f> scene;
    vector<Point2f> scene_corners(4);
    
    detector.detect( gray, kp_image );
    extractor.compute( gray, kp_image, des_image );
    
    int findObject = 0;
    good_matches.clear();
    for(unsigned int i = 0; i < vDesObject.size(); i++ ){
        matcher.knnMatch(vDesObject[i], des_image, matches, 2);
        
        for(int ii = 0; ii < min(des_image.rows-1,(int) matches.size()); ii++) //THIS LOOP IS SENSITIVE TO SEGFAULTS
        {
            if((matches[ii][0].distance < thresholdMatchingNN*(matches[ii][1].distance)) && ((int) matches[ii].size()<=2 && (int) matches[ii].size()>0))
            {
                good_matches.push_back(matches[ii][0]);
            }
        }
        
        if (good_matches.size() >= thresholdGoodMatches){
            findObject = 1;
            break;
        }
    }
    
    if (findObject)
    {
        
        //Display that the object is found
        putText(img, "Object Found", cvPoint(10,50),FONT_HERSHEY_COMPLEX_SMALL, 2, cvScalar(0,0,250), 1, CV_AA);
        int xTotalVal =0, yTotalVal =0;
        xmax = ymax = 0;
        xmin = ymin = 10000;
        obj.clear();
        scene.clear();
        for(unsigned int i = 0; i < good_matches.size(); i++ )
        {
            //Get the keypoints from the good matches
            obj.push_back( kpObject[ good_matches[i].queryIdx ].pt );
            scene.push_back( kp_image[ good_matches[i].trainIdx ].pt );
            
            circle( img, kp_image[ good_matches[i].trainIdx ].pt, 3, Scalar(0,0,255), -1, 8);
            
            txval = kp_image[ good_matches[i].trainIdx ].pt.x;
            tyval = kp_image[ good_matches[i].trainIdx ].pt.y;
            xTotalVal += kp_image[ good_matches[i].trainIdx ].pt.x;
            yTotalVal += kp_image[ good_matches[i].trainIdx ].pt.y;
            //circle( img, kpObject[ good_matches[i].queryIdx ].pt, 3, Scalar(0,255,255), -1, 8);
            
            if(xmin > txval)
                xmin = txval;
            if(ymax < tyval)
                ymax = tyval;
            if(xmax < txval)
                xmax = txval;
            if(ymin > tyval)
                ymin = tyval;
        }
        
        H = findHomography( obj, scene, CV_RANSAC );
        perspectiveTransform( obj_corners, scene_corners, H);
        
        line(img, scene_corners[0], scene_corners[1], Scalar(0, 0, 255), 4 );
        line(img, scene_corners[1], scene_corners[2], Scalar(0, 0, 255), 4 );
        line(img, scene_corners[2], scene_corners[3], Scalar(0, 0, 255), 4 );
        line(img, scene_corners[3], scene_corners[0], Scalar(0, 0, 255), 4 );
        
        //circle( img, kpObject[ good_matches[i].queryIdx ].pt, 3, Scalar(0,255,255), -1, 8);
        
        //        xTotalVal = xTotalVal/good_matches.size();
        //        yTotalVal = yTotalVal/good_matches.size();
        //
        //
        //        Rect newRoiRect(scene_corners[0].x, scene_corners[0].y, scene_corners[3].x - scene_corners[2].x, scene_corners[1].y - scene_corners[2].y);
        //        //Rect newRoiRect(xmin, ymin, xmax-xmin, ymax-ymin);
        //
        ////        cv::Size s = img.size();
        ////        if(newRoiRect.x + newRoiRect.width >= s.width || newRoiRect.y + newRoiRect.height >= s.height || newRoiRect.x <= 0 || newRoiRect.y <= 0)
        ////        {
        ////            cout<<"Can't create NEW ROI \n";
        ////            return true;
        ////        }
        //        m_rc = newRoiRect;
        //        (m_rc.width == 0)?m_rc.width = 10:m_rc.width = m_rc.width;
        //        (m_rc.height == 0)?m_rc.height = 10:m_rc.height = m_rc.height;
        //
        //
        //        // goodfeature (flow) init ==================================================================================================
        //        cv::Size s = img.size();
        //        Mat featureMask = Mat::zeros(s.height, s.width, CV_8UC1);
        //        featureMask(m_rc).setTo(Scalar(255));
        //        //rectangle(featureMask, m_rc, Scalar(255,255,255), 3, CV_FILLED); //3, CV_FILLED
        //        //ellipse(featureMask, Point(rc.width/2, rc.height/2), Size(rc.width/2, rc.height/2), 0, 0, 360, 255, CV_FILLED);
        //        // automatic initialization
        //        points[0].clear();
        //        points[2].clear();
        //
        //        goodFeaturesToTrack(gray, points[0], MAX_COUNT, 0.01, 10, featureMask, 3, 0, 0.04); //10 featureMask
        //        cornerSubPix(gray, points[0], subPixWinSize, Size(-1,-1), termcrit);
        // goodfeature (flow) init end ==================================================================================================
        //        calcOpticalFlowPyrLK(prevGray, gray, points[0], points[1], status, err, winSize,
        //                             3, termcrit, 0, 0.001);
        //
        //        xmax = ymax = 0;
        //        xmin = ymin = 10000;
        //
        //        for( i = k = 0; i < points[1].size(); i++ )
        //        {
        //            if( !status[i] ){
        //                cout << "status error)\n";
        //                continue;
        //            }
        //
        //            txval = points[1].at(i).x;
        //            tyval = points[1].at(i).y;
        //
        //            if(xmin > txval)
        //                xmin = txval;
        //            if(ymax < tyval)
        //                ymax = tyval;
        //            if(xmax < txval)
        //                xmax = txval;
        //            if(ymin > tyval)
        //                ymin = tyval;
        //
        //            circle( img, points[1][i], 3, Scalar(255,255,255), -1, 2);
        //
        //            points[2].push_back(points[1][i]);
        //
        //        }
        //
        //        Rect tRect(xmin, ymin, xmax-xmin, ymax-ymin);
        //        m_rc = tRect;
        
        return true;
        
        //        H = findHomography( obj, scene, CV_RANSAC );
        //        perspectiveTransform( obj_corners, scene_corners, H);
        //
        //        line(img, scene_corners[0], scene_corners[1], Scalar(0, 255, 0), 4 );
        //        line(img, scene_corners[1], scene_corners[2], Scalar(0, 255, 0), 4 );
        //        line(img, scene_corners[2], scene_corners[3], Scalar(0, 255, 0), 4 );
        //        line(img, scene_corners[3], scene_corners[0], Scalar(0, 255, 0), 4 );
        
        //circle( img, kpObject[ good_matches[i].queryIdx ].pt, 3, Scalar(0,255,255), -1, 8);
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //        xTotalVal = xTotalVal/good_matches.size();
        //        yTotalVal = yTotalVal/good_matches.size();
        //
        //
        //        Rect newRoiRect(xTotalVal-newRoiSize/2, yTotalVal-newRoiSize/2, newRoiSize, newRoiSize);
        //        cv::Size s = img.size();
        //        if(newRoiRect.x + newRoiRect.width >= s.width || newRoiRect.y + newRoiRect.height >= s.height || newRoiRect.x <= 0 || newRoiRect.y <= 0)
        //        {
        //            cout<<"Can't create NEW ROI \n";
        //            return true;
        //        }
        //        m_rc = newRoiRect;
        //
        //        //# meanshift add (HSV) //////////////////////////////////////////////////////////////////////////////////////////
        //        float hrange[] = {0,180};
        //        float vrange[] = {0,255};
        //        const float* ranges[] = {hrange, vrange, vrange};	// hue, saturation, brightness
        //        int channels[] = {0, 1, 2};
        //        int hist_sizes[] = {m_param.hist_bins, m_param.hist_bins, m_param.hist_bins};
        //
        //        Mat roi(img, m_rc);
        //        Mat tempMask = Mat::zeros(m_rc.height, m_rc.width, CV_8U);
        //        rectangle(tempMask, m_rc, Scalar(255,255,255), 3, CV_FILLED);
        //        calcHist(&roi, 1, channels, tempMask, m_model3d, 3, hist_sizes, ranges);
        //        Mat hsv;
        //        cvtColor(img, hsv, CV_BGR2HSV);
        //        calcBackProject(&hsv, 1, channels, m_model3d, m_backproj, ranges);
        //
        ////            object = img(m_rc).clone();      // Crop is color CV_8UC3
        ////            cvtColor(object, object, COLOR_BGR2GRAY); // Now crop is grayscale CV_8UC1
        //        cv::imshow("New ROI Image", roi);
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        
    }else{
        
        return false;
        
        //        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //        // # add meanshift (HSV)
        //        int itrs = meanShift(m_backproj, m_rc, TermCriteria( CV_TERMCRIT_EPS | CV_TERMCRIT_ITER, m_param.max_itrs, 1 ));
        //        //cout << "xval:" << m_rc.x << " yval:" << m_rc.y << " width:" << m_rc.width << " height:" << m_rc.height << "\n";
        //        rectangle(img, m_rc, Scalar(0,0,255), 2, CV_AA);
        //
        //        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //        //# meanshift add (HSV)
        //        float hrange[] = {0,180};
        //        float vrange[] = {0,255};
        //        const float* ranges[] = {hrange, vrange, vrange};	// hue, saturation, brightness
        //        int channels[] = {0, 1, 2};
        //        int hist_sizes[] = {m_param.hist_bins, m_param.hist_bins, m_param.hist_bins};
        //        Mat roi(img, m_rc);
        //        Mat tempMask = Mat::zeros(m_rc.height, m_rc.width, CV_8U);
        //        rectangle(tempMask, m_rc, Scalar(255,255,255), 3, CV_FILLED);
        //        calcHist(&roi, 1, channels, tempMask, m_model3d, 3, hist_sizes, ranges);
        //        Mat hsv;
        //        cvtColor(img, hsv, CV_BGR2HSV);
        //        calcBackProject(&hsv, 1, channels, m_model3d, m_backproj, ranges);
        //
        //        //#############################################################
        //        object = img(m_rc).clone();      // Crop is color CV_8UC3
        //        cvtColor(object, object, COLOR_BGR2GRAY); // Now crop is grayscale CV_8UC1
        //        cv::imshow("ROI Image", object);
        //        if (!object.data){
        //            cout<<"Can't create ROI gray image\n";
        //            return true;
        //        }
        //        detector.detect(object, kpObject);
        //        SurfDescriptorExtractor extractor;
        //        extractor.compute(object, kpObject, desObject);
        //
        //        obj_corners[0] = cvPoint(0,0);
        //        obj_corners[1] = cvPoint( object.cols, 0 );
        //        obj_corners[2] = cvPoint( object.cols, object.rows );
        //        obj_corners[3] = cvPoint( 0, object.rows );
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        
    }
    
    return true;
    
}
