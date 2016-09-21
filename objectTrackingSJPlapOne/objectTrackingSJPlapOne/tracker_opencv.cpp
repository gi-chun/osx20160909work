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
    debug_mode = DEBUG_MODE_OFF;
    m_rc = rc;
    
	Mat mask = Mat::zeros(m_rc.height, m_rc.width, CV_8U);
	
    ellipse(mask, Point(m_rc.width/2, m_rc.height/2), Size(m_rc.width/2, m_rc.height/2), 0, 0, 360, 255, CV_FILLED);
    //rectangle(mask, rc, Scalar(255,255,255), 1, CV_AA); //3, CV_FILLED
    
//    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//    Mat roiMat = img(m_rc);
//    Mat roiMask = setRoiObjectMaskOnBackScreen(&roiMat);
//    roiMask.copyTo(featureMask(m_rc));
//    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//    Mat roiMat = img(rc);
//    Mat roiGray;
//    cvtColor(roiMat, roiGray, COLOR_BGR2GRAY);
//    cv::threshold(roiGray,roiGray,SENSITIVITY_VALUE,255,THRESH_BINARY);
//    cv::erode(roiGray, roiGray, noArray());      
//    cv::dilate(roiGray, roiGray, noArray());
//    roiGray.copyTo(featureMask(rc));
//    rectangle(featureMask, rc, Scalar(255,255,255), 3, CV_FILLED); //3, CV_FILLED
//    roiGray.copyTo(featureMask);
//    ellipse(featureMask, Point(rc.width/2, rc.height/2), Size(rc.width/2, rc.height/2), 0, 0, 360, 255, CV_FILLED);
//    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
	if(img.channels()<=1)
	{
		float vrange[] = {0,256};
		const float* phranges = vrange;
		Mat roi(img, rc);
		calcHist(&roi, 1, 0, mask, m_model, 1, &m_param.hist_bins, &phranges);
	}
    else if(m_param.color_model==CM_GRAY)
    {
        Mat gray;
        cvtColor(img, gray, CV_BGR2GRAY);
        
        float vrange[] = {0,256};
        const float* phranges = vrange;
        Mat roi(gray, rc);
        calcHist(&roi, 1, 0, mask, m_model, 1, &m_param.hist_bins, &phranges);
    }
	else if(m_param.color_model==CM_KEYPOINTS)
	{
        //초기화
        m_rc = rc;
        m_prevRc = rc;
        vDesObject.clear();
        points[0].clear();
        points[1].clear();
        points[2].clear();
        ori_points.clear();
        ori_points_temp.clear();
        gray.copyTo(prevGray);
        prev_direction = -1;
        current_findMethod = HOW_FLOW;
        
        roi_width = m_rc.width;
        roi_height = m_rc.height;
        
        saveNewGoodFeature(img, 1);
        
        //keypoints방식 SURF points 생성
        saveNewKeyInfo(img);
        
	}
	else if(m_param.color_model==CM_HUE)
	{
		Mat hsv;
		cvtColor(img, hsv, CV_BGR2HSV);

		float hrange[] = {0,180};
		const float* phranges = hrange;
		int channels[] = {0};
		Mat roi(hsv, rc);
		calcHist(&roi, 1, channels, mask, m_model, 3, &m_param.hist_bins, &phranges);
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
    
    Mat mask = Mat::zeros(rc.height, rc.width, CV_8U);
    ellipse(mask, Point(rc.width/2, rc.height/2), Size(rc.width/2, rc.height/2), 0, 0, 360, 255, CV_FILLED);
    
    if(img.channels()<=1)
    {
        float vrange[] = {0,256};
		const float* phranges = vrange;
		calcBackProject(&img, 1, 0, m_model, m_backproj, &phranges);
	}
    else if(m_param.color_model==CM_GRAY)
    {
        
        Mat gray;
        cvtColor(img, gray, CV_BGR2GRAY);
        
        float vrange[] = {0,256};
        const float* phranges = vrange;
        calcBackProject(&gray, 1, 0, m_model, m_backproj, &phranges);
        
    }
	else if(m_param.color_model==CM_KEYPOINTS)
	{
		cvtColor(img, gray, CV_BGR2GRAY);
        
        if(current_findMethod == HOW_FLOW){
            findObjectFlow(img);
        }else{
            findObjectKeyPoint(img);
        }
        
        rc = m_rc;
        m_prevRc = m_rc;
        
        return true;
        
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
        rectangle(img, m_rc, Scalar(0,0,255), 3, CV_AA);
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
//    m_param.method = MEANSHIFT;
//    m_param.color_model = CM_GRAY;
    /////////////////////////////////////////////////////////////////////////////////////
    
    char sel = -1;
    cout << "  1. camshift\n"
    << "  2. meanshift\n";
    cout << "select tracking method[1-2]: ";
    cin >> sel;
    cout << endl;
    
    if(sel=='1')
        m_param.method = CAMSHIFT;
    else if(sel=='2')
        m_param.method = MEANSHIFT;
    
    cout << "  1. HSV\n"
    << "  2. RGB\n"
    << "  3. hue\n"
    << "  4. gray\n"
    << "  5. key_points\n";
    cout << "select color model[1-5]: ";
    cin >> sel;
    cout << endl;
    
    if(sel=='1')
        m_param.color_model = CM_HSV;
    else if(sel=='2')
        m_param.color_model = CM_RGB;
    else if(sel=='3')
        m_param.color_model = CM_HUE;
    else if(sel=='4')
        m_param.color_model = CM_GRAY;
    else if(sel=='5')
        m_param.color_model = CM_KEYPOINTS;
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

bool tracker_opencv::saveNewGoodFeature(Mat img, int init)
{
    Rect rRec;
    rRec = m_rc;
    if(m_rc.width == 0){
        rRec = m_prevRc;
    }
    
    cv::Size s = img.size();
//    validateROI(&rRec, s);
    
    Mat mask = Mat::zeros(rRec.height, rRec.width, CV_8U);
    ellipse(mask, Point(rRec.width/2, rRec.height/2), Size(rRec.width/2, rRec.height/2), 0, 0, 360, 255, CV_FILLED);
    
    //전체화면중 추적할 ROI영역 마스킹 사각형안의 타원형
    Mat featureMask = Mat::zeros(s.height, s.width, CV_8UC1);
    mask.copyTo(featureMask(rRec));
    //featureMask(m_rc).setTo(Scalar(255));
    cv::imshow("Full ROI MASK Image", featureMask);
    
    //Flow방식 TrackPoints 생성
    cvtColor(img, gray, CV_BGR2GRAY);
    goodFeaturesToTrack(gray, points[0], MAX_COUNT, 0.01, 10, featureMask, 3, 0, 0.04); //10 featureMask
    cornerSubPix(gray, points[0], subPixWinSize, Size(-1,-1), termcrit);
    ori_points = points[0];
    
    //if(init)
    //    init_ori_points = ori_points;
    init_ori_points = ori_points;
    
    return true;
}

bool tracker_opencv::saveNewKeyInfo(Mat img)
{
    Rect rRec;
    rRec = m_rc;
    if(m_rc.width == 0){
        rRec = m_prevRc;
    }
    
//    cv::Size s = img.size();
//    validateROI(&rRec, s);
    
    m_keypoint_rc = rRec;
    
    Mat mask = Mat::zeros(rRec.height, rRec.width, CV_8U);
    ellipse(mask, Point(rRec.width/2, rRec.height/2), Size(rRec.width/2, rRec.height/2), 0, 0, 360, 255, CV_FILLED);
 
    Mat object_temp = img(rRec).clone();      // Crop is color CV_8UC3
    object = cv::Mat(rRec.width, rRec.height, CV_8UC1, img.type());
    object.setTo(cv::Scalar(0,0,0));
    object_temp.copyTo(object, mask); //mask, featureMask
    
    cvtColor(object, object, COLOR_BGR2GRAY); // Now crop is grayscale CV_8UC1
    cv::imshow("ROI Image", object);
    
    if (!object.data){
        cout<<"Can't create ROI gray image\n";
        return false;
    }
    
    int minH;
    minH=100; //중요 (값이 클수록 민감도 낮음) 100->500->
    SurfFeatureDetector detector(minH);
    detector.detect(object, kpObject);
    SurfDescriptorExtractor extractor;
    extractor.compute(object, kpObject, desObject);
    
    if(vDesObject.size() > 10){
        //vDesObject[9] = desObject;
    }else{
        vDesObject.push_back(desObject);
    }
    
    obj_corners[0] = cvPoint(0,0);
    obj_corners[1] = cvPoint( object.cols, 0 );
    obj_corners[2] = cvPoint( object.cols, object.rows );
    obj_corners[3] = cvPoint( 0, object.rows );
    
    //debug
    //        for(unsigned int i = 0; i < kpObject.size(); i++ )
    //        {
    //            //cout<<"surf init kpObject exist \n";
    //            circle( img, kpObject[i].pt, 1, Scalar(0,0,0), -1, 8);
    //        }
    return true;
}

bool tracker_opencv::findObjectFlow(Mat img)
{
    int reInit = 0;
    
    if( !points[0].empty() ){
        if(prevGray.empty())
            gray.copyTo(prevGray);
        
        calcOpticalFlowPyrLK(prevGray, gray, points[0], points[1], status, err, winSize,
                             3, termcrit, 0, 0.001);
        
        xmax = ymax = 0;
        xmin = ymin = 10000;
        
        cout << "points size:" << points[1].size() << "\n";
        
        xroicenter = m_rc.x + m_rc.width/2;
        yroicenter = m_rc.y + m_rc.height/2;
        
        points[2].clear();
        
        if(points[1].size() < SENSITIVITY_LIMIT_FOUND_POINTS ){
            
            std::swap(points[2], points[0]);
            std::swap(ori_points_temp, ori_points);
            gray.copyTo(prevGray);
            points[0].clear();
            points[1].clear();
            points[2].clear();
            ori_points.clear();
            ori_points_temp.clear();
            init_ori_points.clear();
            
            //find object for keypoins
            //m_rc = m_keypoint_rc;     //m_keypoint_rc: find object for keypoints로 찾을때 최근저장한 이미지 영역
            current_findMethod = HOW_KEYPOINTS;
            findObjectKeyPoint(img);
            
            return true;
        }
        
        //            if(points[1].size() < 1)
        //                points[0] = ori_points;
        /////////////////////////////////////////////////////////////////////////////////////
        int flowX = 0; // -1 right, 1 left
        int flowY = 0; // -1 down, 1 up
        int flowXleftCount = 0, flowXrightCount = 0;
        int flowYdownCount = 0, flowYupCount = 0;
        int noMoveCount = 0;
        double total_distance_x = 0, total_distance_y = 0;
        double ori_distance_x = 0, ori_distance_y = 0;
        int check_fail_points = 0; // 1 : check
        int nTotal = 0;
        double d_temp_x = 0, d_temp_y;
        //double d_same_x = 0, d_same_y;
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
            
            //0.3 -> 0.5 -> 1.0 -> 0.2
            d_temp_x = points[0].at(n).x - points[1].at(n).x;
            if(abs(d_temp_x) > SENSITIVITY_MOVE_VALUE && d_temp_x < 0){
                //flow right
                flowXrightCount++;
            }else if(abs(d_temp_x) > SENSITIVITY_MOVE_VALUE && d_temp_x > 0 ){
                flowXleftCount++;
            }
            
            total_distance_y += abs(points[0].at(n).y - points[1].at(n).y);
            ori_distance_y += abs(ori_points.at(n).y - points[1].at(n).y);
            
            d_temp_y = points[0].at(n).y - points[1].at(n).y;
            if(abs(d_temp_y) > SENSITIVITY_MOVE_VALUE && d_temp_y < 0){
                //flow down
                flowYdownCount++;
            }else if(abs(d_temp_y) > SENSITIVITY_MOVE_VALUE && d_temp_y > 0 ){
                flowYupCount++;
            }
            
            //no move count
            if( abs(d_temp_x) < SENSITIVITY_MOVE_VALUE && abs(d_temp_y) < SENSITIVITY_MOVE_VALUE)
                noMoveCount++;
            
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
        
//                    if( noMoveCount < SENSITIVITY_LIMIT_FOUND_POINTS)
//                    {
//                        m_rc.width = 0;m_rc.height = 0;
//        
//                        cout << "hide object so return ******************** no move count: " << noMoveCount << ":" << SENSITIVITY_LIMIT_FOUND_POINTS << ":" << points[1].size() << " \n";
//        
//                        gray.copyTo(prevGray);
//                        points[0].clear();
//                        points[1].clear();
//                        points[2].clear();
//                        ori_points.clear();
//                        ori_points_temp.clear();
//        
//                        return true;
//                    }
        
        //일부 points만 움직임, object를 앞에서 가림, 10%미만인 경우 에러로 확인함
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
                    d_temp_x = flowXrightCount+flowXleftCount;
                    d_temp_y = flowYupCount+flowYdownCount;
        
//                    if(d_temp_x > 0 && d_temp_y > 0){
//                        double tvalue = d_temp_x/points[1].size() * 100;
//                        double ttvalue = d_temp_y/points[1].size() * 100;
//                        cout << "check hide object ******************** tvalue: " << tvalue << ":" << ttvalue << "\n";
//                        cout << "check hide object ******************** move count: " << d_temp_x << ":" << d_temp_y << ":" << points[1].size() << " \n";
//                        if(  tvalue < SENSITIVITY_LIMIT_DIV &&
//                           ttvalue < SENSITIVITY_LIMIT_DIV){
////                        if(  (tvalue > 10.0  && tvalue < 30.0) &&
////                            (ttvalue > 10.0 && ttvalue < 30.0) ){
//        
//                            cout << "hide object so return ******************** move count: " << d_temp_x << ":" << d_temp_y << ":" << points[1].size() << " \n";
//        
//                            std::swap(points[2], points[0]);
//                            std::swap(ori_points_temp, ori_points);
//                            gray.copyTo(prevGray);
//                            points[0].clear();
//                            points[1].clear();
//                            points[2].clear();
//                            ori_points.clear();
//                            ori_points_temp.clear();
//                            init_ori_points.clear();
//                            
//                            //find object for keypoins
//                            m_rc = m_keypoint_rc;
//                            current_findMethod = HOW_KEYPOINTS;
//                            findObjectKeyPoint(img);
//                            
//                            return true;
//        
//                        }
//                    }
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
                
                if( d_temp_x < 0.3 && d_temp_y < 0.3){ //중요 0.3 -> 0.1 작을수록 다른 포인트보다 움직임이 >>>>> 적은것
                    continue;
                }
                
                //to right & up
                if(flowX == -1 && flowY == 1){
                    current_direction = CM_RIGHT_UP;
                }

                // to right & down
                if(flowX == -1 && flowY == -1){
                    current_direction = CM_RIGHT_DOWN;
                }

                // to left & up
                if(flowX == 1 && flowY == 1){
                    current_direction = CM_LEFT_UP;
                }

                // to left & down
                if(flowX == 1 && flowY == -1){
                    current_direction = CM_LEFT_DOWN;
                }
                
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
            
            if(debug_mode == DEBUG_MODE_ON){
                circle( img, points[1][i], 3, Scalar(0,255,0), -1, 8);
                circle( img, points[0][i], 3, Scalar(0,0,255), -1, 8);
                
                line(img, ori_points.at(i), points[1][i], Scalar(255,255,255));
            }
            
            points[2].push_back(points[1][i]);
            ori_points_temp.push_back(ori_points[i]);
            
        }
        
        cout << "init_ori_points.size : points[2].size " << init_ori_points.size() << ":" << points[2].size() << "\n";
        if( (points[2].size() / (double)init_ori_points.size())*100 < 80){ //중요 90 -> 80
            cout << "disapear poins ratio:" << (points[2].size() / (double)init_ori_points.size())*100 << "\n";
            
            std::swap(points[2], points[0]);
            std::swap(ori_points_temp, ori_points);
            gray.copyTo(prevGray);
            points[0].clear();
            points[1].clear();
            points[2].clear();
            ori_points.clear();
            ori_points_temp.clear();
            init_ori_points.clear();
            
            //find object for keypoins
            //m_rc = m_keypoint_rc;     //m_keypoint_rc: find object for keypoints로 찾을때 최근저장한 이미지 영역
            current_findMethod = HOW_KEYPOINTS;
            findObjectKeyPoint(img);
            
            return true;
            
        }
        
        Rect tRect(xmin, ymin, xmax-xmin, ymax-ymin);
        //Rect tRect(xmin, ymin, roi_width, roi_height); //object를 찾았다면 ROI width, height는 처음 찾을당시 ROI유지

        cv::Size s = img.size();
        validateROI(&tRect, s);
        
        m_rc = tRect;
        xroicenter = m_rc.x + m_rc.width/2;
        yroicenter = m_rc.y + m_rc.height/2;
        
        if(prev_direction != current_direction){
            //save new keypoint
            saveNewKeyInfo(img);
        }
        
        if(xmin == 10000 || ymin == 1000 || xmax == 0 || ymax == 0){
            //fail
            cout << "fail faile faile faile \n";
            return true;
        }
        
        rectangle(img, m_rc, Scalar(0,255,0), 3, 4);
        
        cout << "end draw rect ======================> \n";
        
        std::swap(points[2], points[0]);
        std::swap(ori_points_temp, ori_points);
        gray.copyTo(prevGray);
        
        points[2].clear();
        ori_points_temp.clear();
        
    }
    
    return true;
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
    int offset = vDesObject.size();
    for(unsigned int i = 0; i < vDesObject.size(); i++ ){
//        matcher.knnMatch(vDesObject[offset-1], des_image, matches, 2);
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
        //offset--;
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
            
            if(debug_mode == DEBUG_MODE_ON){
                circle( img, kp_image[ good_matches[i].trainIdx ].pt, 3, Scalar(0,0,0), -1, 8);
            }
  
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
        
        Rect tRect(xmin, ymin, xmax-xmin, ymax-ymin);
        cv::Size s = img.size();
        validateROI(&tRect, s);
//        Rect tRect(xmin, ymin, m_prevRc.width, m_prevRc.height);
        m_rc = tRect;
        //m_rc = m_keypoint_rc; //m_keypoint_rc: 최근저장한 이미지 영역, 찾을당시 ROI영역도 포인터를 찾았다면, 해당영역으로 표시
        rectangle(img, m_rc, Scalar(0,0,255), 3, 4);
        
        //find object for flow
        saveNewGoodFeature(img, 0);
        current_findMethod = HOW_FLOW;

//        H = findHomography( obj, scene, CV_RANSAC );
//        perspectiveTransform( obj_corners, scene_corners, H);
//        
//        line(img, scene_corners[0], scene_corners[1], Scalar(255, 0, 0), 4 );
//        line(img, scene_corners[1], scene_corners[2], Scalar(255, 0, 0), 4 );
//        line(img, scene_corners[2], scene_corners[3], Scalar(255, 0, 0), 4 );
//        line(img, scene_corners[3], scene_corners[0], Scalar(255, 0, 0), 4 );
        
        
        return true;
        
    }else{
       
        //find object to flow
        
        //saveNewKeyInfo(img);
        //saveNewGoodFeature(img);
    }
    
    return true;
    
}

void tracker_opencv::validateROI(Rect* rec, cv::Size pS)
{
    //ROI 영역보다 적다면 보정한다.
    if(rec->width/(double)roi_width < 0.10){
        rec->x = rec->x - (abs(roi_width-rec->x))/2;
        //rec->x = rec->x - roi_width*0.25/2;
        rec->width = rec->width + (abs(roi_width-rec->x))/2;
    }
    
    if(rec->height/(double)roi_height < 0.10){
        rec->y = rec->y - (abs(roi_height-rec->y))/2;
        //rec->y = rec->y - roi_height*0.25/2;
        rec->height = rec->height + (abs(roi_height-rec->y))/2;
    }
    
    if(rec->width > roi_width){
        rec->width = roi_width;
    }
    
    if(rec->height > roi_height){
        rec->height = roi_height;
    }
    
    //전체이미지 대응 보정
    (rec->width < 1)?rec->width=10:rec->width;
    (rec->height < 1)?rec->height=10:rec->height;
    
    ((rec->x+rec->width) > pS.width)?rec->width=pS.width-rec->x:rec->width;
    ((rec->y+rec->height) > pS.height)?rec->height=pS.height-rec->y:rec->height;
}
