#ifndef BASBUFFER_H
#define BASBUFFER_H

#include <string>
#include <vector>

namespace BastionPay 
{
#define DEFAULT_BUFFER_SIZE 256

class Buffer {
    public:
        Buffer()
            :databuffer_(NULL)
            ,writecursor_(0)
            ,cap_(0){
            initByCap(DEFAULT_BUFFER_SIZE);
        }
        Buffer(const Buffer &stream)
            :Buffer(){
            this->initByOther(stream);
        }
        ~Buffer(){
            clearandrelease();
        }

        Buffer& operator =(const Buffer &stream){
            if (this != &stream){
                this->initByOther(stream);
            }
            return *this;
        }

        const char* dataPtr()const{
            return this->databuffer_;
        }
        int length()const{
            return this->writecursor_;
        }

        void append(const char *data, int len){
            if (data == NULL || len == 0){
                return;
            }
            this->checkCap(len);

            memcpy(this->databuffer_+this->writecursor_, data, len);
            this->writecursor_ += len;
        }

        bool empty()const{
            return writecursor_ == 0;
        }

        void clear(){
            writecursor_ = 0;
        }

    private:
        void checkCap(int needLen){
            int newlen = this->writecursor_ + needLen - this->cap_;
            if(newlen > 0){
                int cnt = newlen / DEFAULT_BUFFER_SIZE;
                this->initByCap(this->cap_ + DEFAULT_BUFFER_SIZE*(1+cnt));
            }
        }
        void initByCap(int cap){
            if (this->cap_ == cap){
                return;
            }

            char* newdatabuffer = new char[cap];
            int newcap = cap;
            int newcursor = 0;
            memset(newdatabuffer, 0, newcap);
            if (this->databuffer_ != nullptr){
                memcpy(newdatabuffer, this->databuffer_, this->cap_);
                delete []this->databuffer_;
                this->databuffer_ = NULL;

                newcursor = this->writecursor_;
            }

            this->databuffer_ = newdatabuffer;
            this->cap_ = newcap;
            this->writecursor_ = newcursor;
        }
        void initByOther(const Buffer &stream){
            clearandrelease();

            if(stream.cap_ > 0){
                this->cap_ = stream.cap_;
                this->databuffer_ = new char[this->cap_];

                this->writecursor_ = stream.writecursor_;
                memcpy(this->databuffer_, stream.databuffer_, this->cap_);
            }
        }
        void clearandrelease(){
            if(this->databuffer_ != NULL){
                delete []this->databuffer_;
                this->databuffer_ = NULL;
            }

            this->writecursor_ = 0;
            this->cap_ = 0;
        }

    private:
        char* databuffer_;
        int writecursor_;
        int cap_;
};

} // end of namespace BastionPay

#endif
