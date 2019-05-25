//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#ifndef STASK_STREAMINGSINK_H_
#define STASK_STREAMINGSINK_H_

#include "omnetpp.h"
#include "../msg/StreamingMessage_m.h"
#include "ISTask.h"

using namespace omnetpp;

namespace ecsnet {

class StreamingSink : public ISTask{
protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;

};

} /* namespace ecsnet */

#endif /* STASK_STREAMINGSINK_H_ */