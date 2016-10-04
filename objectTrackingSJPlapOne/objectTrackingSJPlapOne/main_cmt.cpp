///////////////////////////////////////////////////////////////////////

//#include "stdafx.h"
#include <iostream>
//#include <windows.h>
#include "tracker_opencv.h"
#include "CMT.h"

using namespace std;

struct CallbackParam
{
	Mat frame;
	Point pt1,pt2;
	Rect roi;
	bool drag;
	bool updated;
};

void onMouse( int event, int x, int y, int flags, void* param )
{
	CallbackParam *p = (CallbackParam *)param;

	if( event == CV_EVENT_LBUTTONDOWN )
	{
		p->pt1.x = x;
		p->pt1.y = y;
		p->pt2 = p->pt1;
		p->drag = true;
	}
	if( event == CV_EVENT_LBUTTONUP )
	{
		int w = x - p->pt1.x;
		int h = y - p->pt1.y;

		p->roi.x = p->pt1.x;
		p->roi.y = p->pt1.y;
		p->roi.width = w;
		p->roi.height = h;
		p->drag = false;

		if(w>=10 && h>=10)
		{
			p->updated = true;
		}
	}
	if( p->drag && event == CV_EVENT_MOUSEMOVE )
	{
		if(p->pt2.x != x || p->pt2.y != y)
		{
			Mat img = p->frame.clone();
			p->pt2.x = x;
			p->pt2.y = y;
			rectangle(img, p->pt1, p->pt2, Scalar(0,255,0), 1);
			imshow("image", img);
		}
	}
}

void proc_video(VideoCapture *vc, int type)
{
    CMT cmt;
    Mat frame;
    
    *vc >> frame;
    
    if(type == 3){
        // 크기 변경
        resize(frame, frame, Size(1280,720));
        // 영상 반전(flip)
        flip(frame, frame, -1);// vertial & horizontal flip
    }
    
    imshow("image", frame);
    
    CallbackParam param;
    param.frame = frame;
    param.drag = false;
    param.updated = false;
    setMouseCallback("image", onMouse, &param);
    
    /////////////////////////////////////////////////
//	tracker_opencv tracker;
//	tracker.configure();

	bool tracking = false;
	while(1)
	{
        
        // image acquisition & target init
		if(param.drag)
		{
		    if( waitKey(10) == 27 ) break;		// ESC key
			continue;
		}
		if(param.updated)
		{
//            if(type == 3){
//                // 크기 변경
//                resize(frame, frame, Size(1280,720));
//                // 영상 반전(flip)
//                flip(frame, frame, -1);// vertial & horizontal flip
//            }
            
			Rect rc = param.roi;
			//tracker.init(frame, rc);
            cv::Mat im_gray;
            cv::cvtColor(frame, im_gray, CV_RGB2GRAY);
            cv::Point2f initTopLeft(rc.x, rc.y);
            cv::Point2f initBottomDown(rc.x+rc.width,rc.y+rc.height);
            tracking = cmt.initialise(im_gray, initTopLeft, initBottomDown);
            
			param.updated = false;
			//tracking = true;
		}
        *vc >> frame;
        param.frame = frame;
        
        if(frame.empty()){
            if(type == 3){
                if(vc) delete vc;
                vc = new VideoCapture("/Users/gclee/Documents/IMG_0793.MOV");
                if (!vc->isOpened())
                {
                    cout << "can't open video file" << endl;
                    return;
                }
                continue;
            }else{
                break;
            }
        }
        
        if(type == 3){
            // 크기 변경
            resize(frame, frame, Size(1280,720));
            //resize(frame, frame, Size(), 0.5, 0.5);//scalex, scaley
            // 영상 반전(flip)
            //flip(frame, frame, 0);// vertical flip
            //flip(frame, frame, 1);// horizontal flip
            flip(frame, frame, -1);// vertial & horizontal flip
            
            param.frame = frame;
        }
	
		// image processing
		if(tracking)
		{
			Rect rc;
			//bool ok = tracker.run(frame, rc);
            cv::Mat im_gray;
            cv::cvtColor(frame, im_gray, CV_RGB2GRAY);
            cmt.processFrame(im_gray);
            
            if(cmt.hasResult){
                for(int i = 0; i<cmt.trackedKeypoints.size(); i++)
                    cv::circle(frame, cmt.trackedKeypoints[i].first.pt, 3, cv::Scalar(255,255,255));
                
//                cv::line(frame, cmt.topLeft, cmt.topRight, cv::Scalar(255,255,255));
//                cv::line(frame, cmt.topRight, cmt.bottomRight, cv::Scalar(255,255,255));
//                cv::line(frame, cmt.bottomRight, cmt.bottomLeft, cv::Scalar(255,255,255));
//                cv::line(frame, cmt.bottomLeft, cmt.topLeft, cv::Scalar(255,255,255));
                
                rectangle(frame, cmt.boundingbox, Scalar(0,0,255), 1, 4);
                //draw some crosshairs around the object
                int x, y = 0;
                x = cmt.boundingbox.x+cmt.boundingbox.width/2;
                y = cmt.boundingbox.y+cmt.boundingbox.height/2;
                circle(frame,Point(x,y),10,Scalar(0,255,0),1);
                line(frame,Point(x,y),Point(x,y-15),Scalar(0,255,0),1);
                line(frame,Point(x,y),Point(x,y+15),Scalar(0,255,0),1);
                line(frame,Point(x,y),Point(x-15,y),Scalar(0,255,0),1);
                line(frame,Point(x,y),Point(x+15,y),Scalar(0,255,0),1);
            }
            
		}

		// image display
		imshow("image", frame);

		// user input
		char ch = waitKey(10);
		if( ch == 27 ) break;	// ESC Key (exit)
		else if(ch == 32 )	// SPACE Key (pause)
		{
//            (tracker.debug_mode == 0)?tracker.debug_mode = 1:tracker.debug_mode = 0;
            
			while((ch = waitKey(10)) != 32 && ch != 27);
			if(ch == 27) break;
		}
	}
    //end while
}

int main()
{
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // test
    
//	VideoCapture *vc = NULL;
//    
//    vc = new VideoCapture(0);
//    if (!vc->isOpened())
//    {
//        cout << "can't open camera" << endl;
//        return 0;
//    }
//    vc->set(CV_CAP_PROP_FRAME_WIDTH, 640);
//    vc->set(CV_CAP_PROP_FRAME_HEIGHT, 480);
//    
//    if(vc) proc_video(vc);
//    if(vc) delete vc;
//    
//    destroyAllWindows();
//    
//    return 0;
    
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
//    //select image source
    char data_src;
    //1 640 * 480
    //1 1920 * 1080
    
    cout << "1. camera input (640 x 480)\n"
    << "2. camera input (320 x 240)\n"
    << "3. video file input\n"
    << endl
    << "select video source[1-3]: ";
    cin >> data_src;
    
    VideoCapture *vc = NULL;
    int nType = 0;
    
    if(data_src=='1')
	{
        nType = 1;
		//camera (vga)
		vc = new VideoCapture(0);
		if (!vc->isOpened())
		{
			cout << "can't open camera" << endl;
			return 0;
		}
		vc->set(CV_CAP_PROP_FRAME_WIDTH, 640);
		vc->set(CV_CAP_PROP_FRAME_HEIGHT, 480);
	}
	else if(data_src=='2')
	{
        nType = 2;
		//camera (qvga)
		vc = new VideoCapture(0);
		if (!vc->isOpened())
		{
			cout << "can't open camera" << endl;
			return 0;
		}
		vc->set(CV_CAP_PROP_FRAME_WIDTH, 320);
		vc->set(CV_CAP_PROP_FRAME_HEIGHT, 240);
	}
	else if(data_src=='3')
	{
        nType = 3;
        
		//video (avi)
//		OPENFILENAME ofn;
//		char szFile[MAX_PATH] = "";
//		ZeroMemory(&ofn, sizeof(OPENFILENAME));
//		ofn.lStructSize = sizeof(OPENFILENAME);
//		ofn.hwndOwner = NULL;
//		ofn.lpstrFile = szFile;
//		ofn.nMaxFile = sizeof(szFile);
//		ofn.lpstrFilter = _T("Avi Files(*.avi)\0*.avi\0All Files (*.*)\0*.*\0");
//		ofn.nFilterIndex = 1;
//		ofn.lpstrFileTitle = NULL;
//		ofn.nMaxFileTitle = 0;
//		ofn.lpstrInitialDir = NULL;
//		ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
//		if(::GetOpenFileName(&ofn)==false) return 0;
//
		//vc = new VideoCapture("/Users/gclee/Documents/sjplabProject/objectTrackingSJPlapOne/uhd_sample.mp4");
        vc = new VideoCapture("/Users/gclee/Documents/IMG_0793.MOV");
		if (!vc->isOpened())
		{
			cout << "can't open video file" << endl;
			return 0;
		}
	}
    if(vc){
        proc_video(vc, nType);
    }
	if(vc) delete vc;

	destroyAllWindows();

	return 0;
}
