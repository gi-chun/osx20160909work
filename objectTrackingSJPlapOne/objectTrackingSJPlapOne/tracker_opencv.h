///////////////////////////////////////////////////////////////////////
// OpenCV tracking example.
// Written by darkpgmr (http://darkpgmr.tistory.com), 2013

#pragma once

// include opencv
#include <opencv2/opencv.hpp>
#include "opencv2/core/core.hpp"
#include "opencv2/highgui/highgui.hpp"
#include "opencv2/imgproc/imgproc.hpp"
#include "opencv2/video/video.hpp"

#include "opencv2/features2d/features2d.hpp"
#include "opencv2/calib3d/calib3d.hpp"
#include "opencv2/nonfree/nonfree.hpp"
//#include "opencv2/video/tracking.hpp"

using namespace cv;

enum {CM_GRAY, CM_HUE, CM_RGB, CM_HSV, CM_KEYPOINTS};	// color model
enum {CM_RIGHT_UP, CM_RIGHT_DOWN, CM_LEFT_UP, CM_LEFT_DOWN};
enum {MEANSHIFT, CAMSHIFT}; // method
enum {HOW_FLOW, HOW_KEYPOINTS};
enum {DEBUG_MODE_ON, DEBUG_MODE_OFF};

//gclee add
const int MAX_COUNT = 500;
const Size subPixWinSize(10,10);
const Size winSize(31,31); //31, 31 , 10, 10
const TermCriteria termcrit(TermCriteria::COUNT|TermCriteria::EPS,20,0.03);
//gclee add end
//gclee add keypoint
const char escapeKey='k';
const double frameCount = 0;
const float thresholdMatchingNN=0.7; //0.7->0.8 -> 0.5
const unsigned int thresholdGoodMatches=10;
const unsigned int thresholdGoodMatchesV[]={4,5,6,7,8,9,10};
const int minHess=250; //2000 -> 500 -> 250
const int newRoiSize=80; //100
const static int SENSITIVITY_VALUE = 20; //20 -> 100 -> 120
const static double SENSITIVITY_MOVE_VALUE = 0.3;
const static int SENSITIVITY_LIMIT_DIV = 40; //40% 이상 점들이 같이 움직였다면 정상 , 10% 미안은 정상처리 ?
const static int SENSITIVITY_LIMIT_NOMOVE = 2;
const static int SENSITIVITY_LIMIT_FOUND_POINTS = 4;

//gclee add keypoint end

struct tracker_opencv_param
{
	int hist_bins;
	int max_itrs;
	int color_model;
	int method;

	tracker_opencv_param()
	{
		hist_bins = 16;
		max_itrs = 10;
		color_model = CM_HSV;
		method = CAMSHIFT;
	}
};

class tracker_opencv
{
public:
	tracker_opencv(void);
	~tracker_opencv(void);

	void init(Mat img, Rect rc);
	bool run(Mat img, Rect& rc);
    
    bool findObjectKeyPoint(Mat img);
    bool findObjectFlow(Mat img);
    bool saveNewKeyInfo(Mat img);
    bool saveNewGoodFeature(Mat img, int init = 0);
    bool isEqualKeyPoint(Mat target, Mat source);
    Mat setRoiObjectMaskOnBackScreen(Mat* roiMat);
    void validateROI(Rect* rec, cv::Size p);

	void configure();
	Mat get_bp_image();

protected:
	Mat m_model;
	MatND m_model3d;
	Mat m_backproj;
	Rect m_rc;
    Rect m_keypoint_rc;
    tracker_opencv_param m_param;
    //gclee add
    Rect m_prevRc;
    Mat gray, prevGray;
    vector<Point2f> points[3];
    vector<Point2f> ori_points;
    vector<Point2f> init_ori_points;
    vector<Point2f> ori_points_temp;
    vector<uchar> status;
    vector<float> err;
    size_t i, k;
    float xmin, ymax, xmax, ymin, txval, tyval;
    float xroicenter, yroicenter;
    //gclee add end
    //gclee add keypoint
    Mat object;
    Mat desObject;
    vector<KeyPoint> kpObject;
    vector<Mat> vDesObject;             //추적대상 keypoint포함 이미지 저장소
    SurfFeatureDetector detector;
    SurfDescriptorExtractor extractor;
    FlannBasedMatcher matcher;
    int roi_width;
    int roi_height;
    int current_direction;
    int prev_direction;
    int current_findMethod;
    
public:
    int debug_mode;
    
    //gclee add keypoint end
    
};
